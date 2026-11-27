//! Cross-platform window focus, unminimize, and attention handling for
//! interactive browser prompts (passkey sign-in/registration, browser
//! association approval, and unlock requests), plus Windows desktop identity
//! helpers (AppUserModelID, main HWND tracking, and native `.ico` application
//! icon assignment).
//!
//! When the user triggers a passkey in their browser while friendlypass is
//! hidden in the status area, minimized, or behind other windows:
//! 1. The background bridge thread calls [`WindowFocusDriver::wake_from_background`]
//!    so hidden/minimized OS windows (which pause egui repaints) are restored right away.
//! 2. On the GUI thread, [`WindowFocusCoordinator`] tracks the active prompt key
//!    and raises the window once per prompt: `Minimized(false)`, `Visible(true)`,
//!    `WindowLevel::AlwaysOnTop`, `RequestUserAttention(Critical)`, `Focus`, plus
//!    native macOS/Windows activation.
//! 3. When the prompt closes (confirm, cancel, Escape, or timeout), the
//!    coordinator resets `WindowLevel::Normal`, clears user attention,
//!    re-hides or re-minimizes if the window was hidden/minimized before, and
//!    hands focus back to the previously active application (e.g. the browser)
//!    when friendlypass was in the background.

use std::sync::Arc;

use eframe::egui;

/// Native pre-activation state captured before raising friendlypass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FocusSnapshot {
    /// Platform handle to the previously active application/window:
    /// - macOS: `pid_t` of the previous frontmost `NSRunningApplication`
    /// - Windows: `HWND` (as `isize`) of the previous foreground window
    /// - Linux / none: `0`
    pub prev_handle: isize,
    pub was_minimized: bool,
    /// Window was hidden to the status area (tray / menu bar) before raising.
    pub was_hidden: bool,
    pub was_focused: bool,
}

/// Platform window-focus hook (injected so headless tests never steal desktop focus).
pub trait WindowFocusDriver: Send + Sync {
    /// Called from a background thread when an interactive prompt arrives, to
    /// wake a hidden or minimized window whose event loop might be paused.
    fn wake_from_background(&self);

    /// Called on the GUI thread when a prompt opens. Returns the pre-prompt
    /// window/foreground snapshot (either captured during `wake_from_background`
    /// or captured right now) and brings the native window forward.
    ///
    /// When `stay_on_top` is `true`, the native layer may keep the window
    /// topmost until [`Self::restore_after_prompt`] is called.
    fn activate_for_prompt(&self, ctx: &egui::Context, stay_on_top: bool) -> FocusSnapshot;

    /// Called on the GUI thread after a transient confirmation prompt closes,
    /// to drop any native topmost flag and hand focus back to `prev_handle`
    /// (when non-zero).
    fn restore_after_prompt(&self, prev_handle: isize);

    /// Explicitly show, unminimize, and focus the main window (e.g. when the
    /// user clicks the status-area / tray icon).
    fn show_main_window(&self) {}
}

/// No-op driver used by `App::default()` and headless `egui_kittest` runs.
#[derive(Default)]
pub struct NoopWindowFocus;

impl WindowFocusDriver for NoopWindowFocus {
    fn wake_from_background(&self) {}

    fn activate_for_prompt(&self, ctx: &egui::Context, _stay_on_top: bool) -> FocusSnapshot {
        let (was_minimized, was_focused) = ctx.input(|i| {
            (
                i.viewport().minimized.unwrap_or(false),
                i.viewport().focused.unwrap_or(true),
            )
        });
        FocusSnapshot {
            prev_handle: 0,
            was_minimized,
            was_hidden: false,
            was_focused,
        }
    }

    fn restore_after_prompt(&self, _prev_handle: isize) {}
}

/// Real OS driver for desktop runs (`App::new`).
#[derive(Default)]
pub struct SystemWindowFocus {
    #[cfg(windows)]
    pending_wake: std::sync::Mutex<Option<FocusSnapshot>>,
}

impl WindowFocusDriver for SystemWindowFocus {
    fn wake_from_background(&self) {
        #[cfg(target_os = "macos")]
        {
            macos_impl::wake_from_background();
        }
        #[cfg(windows)]
        {
            let snap = windows_impl::wake_and_raise(true);
            let mut slot = self
                .pending_wake
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_none() {
                *slot = Some(snap);
            }
        }
    }

    fn activate_for_prompt(&self, ctx: &egui::Context, stay_on_top: bool) -> FocusSnapshot {
        #[cfg(target_os = "macos")]
        {
            let _ = (ctx, stay_on_top);
            macos_impl::activate_for_prompt()
        }
        #[cfg(windows)]
        {
            let _ = ctx;
            let cached = self
                .pending_wake
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let live = windows_impl::wake_and_raise(stay_on_top);
            cached.unwrap_or(live)
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = stay_on_top;
            let (was_minimized, was_focused) = ctx.input(|i| {
                (
                    i.viewport().minimized.unwrap_or(false),
                    i.viewport().focused.unwrap_or(false),
                )
            });
            FocusSnapshot {
                prev_handle: 0,
                was_minimized,
                was_hidden: false,
                was_focused,
            }
        }
    }

    fn restore_after_prompt(&self, prev_handle: isize) {
        #[cfg(target_os = "macos")]
        {
            macos_impl::restore_app(prev_handle);
        }
        #[cfg(windows)]
        {
            *self
                .pending_wake
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            windows_impl::restore_window(prev_handle);
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let _ = prev_handle;
        }
    }

    fn show_main_window(&self) {
        #[cfg(target_os = "macos")]
        {
            macos_impl::show_main_window();
        }
        #[cfg(windows)]
        {
            *self
                .pending_wake
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            windows_impl::show_main_window();
        }
    }
}

/// Identifies which interactive confirmation prompt is currently holding focus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivePrompt {
    Passkey(u64),
    Approval(String),
}

/// Tracks one-shot raise/restore transitions across frames so we raise once
/// per incoming prompt, keep the original restore target across back-to-back
/// queued prompts, and always drop `AlwaysOnTop` once no prompt is pending.
pub struct WindowFocusCoordinator {
    driver: Arc<dyn WindowFocusDriver>,
    active: Option<ActivePrompt>,
    restore: Option<FocusSnapshot>,
}

impl WindowFocusCoordinator {
    pub fn new(driver: Arc<dyn WindowFocusDriver>) -> Self {
        Self {
            driver,
            active: None,
            restore: None,
        }
    }

    pub fn driver(&self) -> Arc<dyn WindowFocusDriver> {
        Arc::clone(&self.driver)
    }

    pub fn set_driver(&mut self, driver: Arc<dyn WindowFocusDriver>) {
        self.driver = driver;
    }

    /// Synchronize window visibility/focus with the currently active transient
    /// browser confirmation prompt (`Some`) or lack thereof (`None`).
    pub fn sync_prompt(&mut self, ctx: &egui::Context, current: Option<ActivePrompt>) {
        if self.active == current {
            return;
        }
        match current {
            Some(prompt) => {
                let snap = self.driver.activate_for_prompt(ctx, true);
                // Preserve the original pre-prompt snapshot when a second
                // prompt arrives back-to-back while we are already raised.
                if self.restore.is_none() {
                    self.restore = Some(snap);
                }
                self.active = Some(prompt);

                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                    egui::WindowLevel::AlwaysOnTop,
                ));
                ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                    egui::UserAttentionType::Critical,
                ));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            None => {
                self.active = None;
                let restore = self.restore.take();

                ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                    egui::WindowLevel::Normal,
                ));
                ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                    egui::UserAttentionType::Reset,
                ));
                let prev_to_restore = restore.as_ref().map_or(0, |snap| {
                    if !snap.was_focused {
                        snap.prev_handle
                    } else {
                        0
                    }
                });
                self.driver.restore_after_prompt(prev_to_restore);
                if let Some(snap) = restore {
                    if snap.was_hidden {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    } else if snap.was_minimized {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                }
            }
        }
    }

    /// One-shot raise for an unlock request (does not pin `AlwaysOnTop` or
    /// auto-minimize/re-hide afterwards so the user can interact with the unlock screen).
    pub fn raise_for_unlock(&mut self, ctx: &egui::Context) {
        let _ = self.driver.activate_for_prompt(ctx, false);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Critical,
        ));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Explicitly show, unminimize, and focus the window (e.g. from the status
    /// area icon). If a transient prompt was holding a `was_hidden` or
    /// `was_minimized` restore flag, clear it so the window stays open.
    pub fn show_and_focus(&mut self, ctx: &egui::Context) {
        self.clear_hidden_restore();
        self.driver.show_main_window();
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Cancel any pending auto-hide / auto-minimize on a currently active prompt
    /// (called when the user explicitly requests to show the main window).
    pub fn clear_hidden_restore(&mut self) {
        if let Some(snap) = self.restore.as_mut() {
            snap.was_hidden = false;
            snap.was_minimized = false;
        }
    }

    pub fn active_prompt(&self) -> Option<&ActivePrompt> {
        self.active.as_ref()
    }

    pub fn pending_restore(&self) -> Option<FocusSnapshot> {
        self.restore
    }
}

/// Set the Windows AppUserModelID before creating any windows so taskbar
/// pinning associates the pinned shortcut with `friendlypass-gui.exe` and its
/// embedded icon resource. No-op on non-Windows platforms.
pub fn init_platform_app_id() {
    #[cfg(windows)]
    windows_impl::init_app_user_model_id();
}

/// Record the main window's native handle on Windows and assign both
/// `ICON_BIG` and `ICON_SMALL` from the executable's embedded icon resource so
/// the titlebar, Alt+Tab switcher, and taskbar all show the crisp `.ico`.
#[cfg(windows)]
pub fn register_windows_main_hwnd(hwnd: isize) {
    windows_impl::register_main_hwnd(hwnd);
    windows_impl::apply_embedded_window_icons(hwnd);
}

/// Bring the main window back to the foreground from a background thread (used
/// by the status-area tray icon on click).
pub fn show_main_window_native() {
    #[cfg(target_os = "macos")]
    macos_impl::show_main_window();
    #[cfg(windows)]
    windows_impl::show_main_window();
}

// ---------------------------------------------------------------------------
// macOS implementation (via src/macos_window.m)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::FocusSnapshot;

    extern "C" {
        fn fp_macos_wake_from_background();
        fn fp_macos_show_main_window();
        fn fp_macos_activate_for_prompt(
            out_prev_pid: *mut i32,
            out_was_minimized: *mut bool,
            out_was_hidden: *mut bool,
            out_was_focused: *mut bool,
        );
        fn fp_macos_restore_app_pid(pid: i32);
    }

    pub fn wake_from_background() {
        unsafe { fp_macos_wake_from_background() };
    }

    pub fn show_main_window() {
        unsafe { fp_macos_show_main_window() };
    }

    pub fn activate_for_prompt() -> FocusSnapshot {
        let mut prev_pid: i32 = 0;
        let mut was_minimized = false;
        let mut was_hidden = false;
        let mut was_focused = false;
        unsafe {
            fp_macos_activate_for_prompt(
                &mut prev_pid,
                &mut was_minimized,
                &mut was_hidden,
                &mut was_focused,
            );
        }
        FocusSnapshot {
            prev_handle: prev_pid as isize,
            was_minimized,
            was_hidden,
            was_focused,
        }
    }

    pub fn restore_app(prev_handle: isize) {
        if let Ok(pid) = i32::try_from(prev_handle) {
            if pid > 0 {
                unsafe { fp_macos_restore_app_pid(pid) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation (via windows-sys)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_impl {
    use std::sync::atomic::{AtomicIsize, Ordering};

    use super::FocusSnapshot;
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, EnumWindows, GetForegroundWindow, GetSystemMetrics, GetWindow,
        GetWindowLongW, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, LoadImageW,
        SendMessageW, SetForegroundWindow, SetWindowPos, ShowWindowAsync, GWL_STYLE, GW_OWNER,
        HWND_NOTOPMOST, HWND_TOPMOST, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_SHARED, SM_CXICON,
        SM_CXSMICON, SM_CYICON, SM_CYSMICON, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
        SWP_SHOWWINDOW, SW_RESTORE, SW_SHOW, WM_SETICON, WS_CAPTION,
    };

    const APP_USER_MODEL_ID: &str = "org.friendlypass.friendlypass";

    static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);

    pub fn init_app_user_model_id() {
        let wide: Vec<u16> = APP_USER_MODEL_ID
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(wide.as_ptr());
        }
    }

    pub fn register_main_hwnd(hwnd: isize) {
        if hwnd != 0 {
            MAIN_HWND.store(hwnd, Ordering::Relaxed);
        }
    }

    pub fn apply_embedded_window_icons(hwnd_raw: isize) {
        if hwnd_raw == 0 {
            return;
        }
        unsafe {
            let hwnd = hwnd_raw as HWND;
            let hinst = GetModuleHandleW(std::ptr::null());
            if hinst.is_null() {
                return;
            }
            // Resource ID 1 is the application icon embedded by winresource in build.rs.
            let res_id = 1usize as *const u16;
            let big = LoadImageW(
                hinst,
                res_id,
                IMAGE_ICON,
                GetSystemMetrics(SM_CXICON),
                GetSystemMetrics(SM_CYICON),
                LR_SHARED,
            );
            if !big.is_null() {
                SendMessageW(hwnd, WM_SETICON, ICON_BIG as WPARAM, big as LPARAM);
            }
            let small = LoadImageW(
                hinst,
                res_id,
                IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON),
                GetSystemMetrics(SM_CYSMICON),
                LR_SHARED,
            );
            if !small.is_null() {
                SendMessageW(hwnd, WM_SETICON, ICON_SMALL as WPARAM, small as LPARAM);
            }
        }
    }

    struct FindWindowCtx {
        self_pid: u32,
        found: HWND,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam as *mut FindWindowCtx);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != ctx.self_pid {
            return 1;
        }
        // Main top-level window has no owner and has a caption bar (this skips
        // our hidden tray helper window even when the main window is hidden).
        let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
        if GetWindow(hwnd, GW_OWNER).is_null() && (style & WS_CAPTION) != 0 {
            ctx.found = hwnd;
            return 0;
        }
        1
    }

    fn find_own_main_window() -> HWND {
        let cached = MAIN_HWND.load(Ordering::Relaxed);
        if cached != 0 {
            let hwnd = cached as HWND;
            if unsafe { IsWindow(hwnd) } != 0 {
                return hwnd;
            }
        }
        let mut ctx = FindWindowCtx {
            self_pid: unsafe { GetCurrentProcessId() },
            found: std::ptr::null_mut(),
        };
        unsafe {
            EnumWindows(Some(enum_proc), (&mut ctx as *mut FindWindowCtx) as LPARAM);
        }
        if !ctx.found.is_null() {
            MAIN_HWND.store(ctx.found as isize, Ordering::Relaxed);
        }
        ctx.found
    }

    pub fn show_main_window() {
        unsafe {
            let own = find_own_main_window();
            if own.is_null() {
                return;
            }
            if IsIconic(own) != 0 {
                ShowWindowAsync(own, SW_RESTORE);
            } else {
                ShowWindowAsync(own, SW_SHOW);
            }
            BringWindowToTop(own);
            SetForegroundWindow(own);
        }
    }

    pub fn wake_and_raise(stay_on_top: bool) -> FocusSnapshot {
        unsafe {
            let self_pid = GetCurrentProcessId();
            let fg = GetForegroundWindow();
            let mut fg_pid = 0u32;
            if !fg.is_null() {
                GetWindowThreadProcessId(fg, &mut fg_pid);
            }
            let was_focused = !fg.is_null() && fg_pid == self_pid;
            let prev_handle = if !fg.is_null() && fg_pid != self_pid {
                fg as isize
            } else {
                0
            };

            let own = find_own_main_window();
            let was_minimized = !own.is_null() && IsIconic(own) != 0;
            let was_hidden = !own.is_null() && IsWindowVisible(own) == 0 && !was_minimized;

            if !own.is_null() {
                if was_minimized {
                    ShowWindowAsync(own, SW_RESTORE);
                } else if was_hidden {
                    ShowWindowAsync(own, SW_SHOW);
                }
                // Place topmost so the confirmation floats visibly over the
                // browser even if Windows foreground lock blocks SetForegroundWindow.
                SetWindowPos(
                    own,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
                );
                if !stay_on_top {
                    SetWindowPos(
                        own,
                        HWND_NOTOPMOST,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
                    );
                }
                BringWindowToTop(own);
                SetForegroundWindow(own);
            }

            FocusSnapshot {
                prev_handle,
                was_minimized,
                was_hidden,
                was_focused,
            }
        }
    }

    pub fn restore_window(prev_handle: isize) {
        unsafe {
            let own = find_own_main_window();
            if !own.is_null() {
                SetWindowPos(
                    own,
                    HWND_NOTOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                );
            }
            if prev_handle != 0 {
                let hwnd = prev_handle as HWND;
                if IsWindow(hwnd) != 0 {
                    SetForegroundWindow(hwnd);
                }
            }
        }
    }
}
