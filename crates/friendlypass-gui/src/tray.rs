//! System status-area (Windows notification area / macOS menu bar) icon for
//! "Close to status area".
//!
//! When enabled, closing the main window hides friendlypass instead of exiting
//! so browser autofill and passkeys continue working in the background. Users
//! can restore, lock, or quit from the status-area icon.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use eframe::egui;

/// User action triggered from the status-area icon or its context menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayCommand {
    Show,
    Lock,
    Quit,
}

/// Whether the current platform implements a native status-area icon.
pub fn is_supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Pluggable tray backend (headless tests use [`NoopTrayBackend`] or a mock).
pub trait TrayBackend: Send + Sync {
    /// Whether this backend actually provides a status-area icon.
    fn is_supported(&self) -> bool;
    /// Ensure the status-area icon matches `enabled` and reflects `unlocked`.
    fn sync(&self, enabled: bool, unlocked: bool);
    /// Drain queued commands triggered since the last frame.
    fn drain_commands(&self) -> Vec<TrayCommand>;
    /// Attach the `egui::Context` so tray clicks wake a hidden/sleeping UI loop.
    fn set_egui_ctx(&self, ctx: &egui::Context);
}

/// No-op backend used by `App::default()` and headless `egui_kittest` tests.
#[derive(Default)]
pub struct NoopTrayBackend;

impl TrayBackend for NoopTrayBackend {
    fn is_supported(&self) -> bool {
        false
    }
    fn sync(&self, _enabled: bool, _unlocked: bool) {}
    fn drain_commands(&self) -> Vec<TrayCommand> {
        Vec::new()
    }
    fn set_egui_ctx(&self, _ctx: &egui::Context) {}
}

#[derive(Default)]
struct TrayShared {
    commands: Mutex<VecDeque<TrayCommand>>,
    egui_ctx: Mutex<Option<egui::Context>>,
    unlocked: AtomicBool,
}

impl TrayShared {
    fn push(&self, cmd: TrayCommand) {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(cmd);
        if cmd == TrayCommand::Show {
            crate::window_focus::show_main_window_native();
        }
        if let Some(ctx) = self
            .egui_ctx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            ctx.request_repaint();
        }
    }

    fn drain(&self) -> Vec<TrayCommand> {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect()
    }

    fn set_egui_ctx(&self, ctx: &egui::Context) {
        let mut slot = self
            .egui_ctx
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(ctx.clone());
        }
    }
}

/// Native OS status-area backend installed by `App::new`.
pub struct SystemTrayBackend {
    shared: Arc<TrayShared>,
    #[cfg(windows)]
    worker: Mutex<Option<windows_impl::WinTrayWorker>>,
    #[cfg(target_os = "macos")]
    last_state: Mutex<Option<(bool, bool)>>,
}

impl Default for SystemTrayBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemTrayBackend {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(TrayShared::default()),
            #[cfg(windows)]
            worker: Mutex::new(None),
            #[cfg(target_os = "macos")]
            last_state: Mutex::new(None),
        }
    }
}

impl TrayBackend for SystemTrayBackend {
    fn is_supported(&self) -> bool {
        is_supported()
    }

    fn sync(&self, enabled: bool, unlocked: bool) {
        self.shared.unlocked.store(unlocked, Ordering::Relaxed);

        #[cfg(windows)]
        {
            let mut slot = self
                .worker
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if enabled {
                if slot.is_none() {
                    *slot = windows_impl::start(Arc::clone(&self.shared));
                }
            } else if let Some(worker) = slot.take() {
                worker.stop();
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut last = self
                .last_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *last == Some((enabled, unlocked)) {
                return;
            }
            *last = Some((enabled, unlocked));
            macos_impl::sync(Arc::clone(&self.shared), enabled, unlocked);
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (enabled, unlocked);
        }
    }

    fn drain_commands(&self) -> Vec<TrayCommand> {
        self.shared.drain()
    }

    fn set_egui_ctx(&self, ctx: &egui::Context) {
        self.shared.set_egui_ctx(ctx);
    }
}

impl Drop for SystemTrayBackend {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(worker) = self
                .worker
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                worker.stop();
            }
        }
        #[cfg(target_os = "macos")]
        {
            macos_impl::disable();
        }
    }
}

// ---------------------------------------------------------------------------
// macOS implementation (via src/macos_tray.m)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_impl {
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    use super::{TrayCommand, TrayShared};

    type FpTrayCallback = extern "C" fn(i32);

    extern "C" {
        fn fp_macos_tray_sync(
            enabled: bool,
            unlocked: bool,
            icon_png: *const u8,
            icon_len: usize,
            callback: FpTrayCallback,
        );
    }

    static ACTIVE_SHARED: OnceLock<Mutex<Option<Arc<TrayShared>>>> = OnceLock::new();

    fn shared_slot() -> &'static Mutex<Option<Arc<TrayShared>>> {
        ACTIVE_SHARED.get_or_init(|| Mutex::new(None))
    }

    extern "C" fn tray_callback(action: i32) {
        let cmd = match action {
            1 => TrayCommand::Show,
            2 => TrayCommand::Lock,
            3 => TrayCommand::Quit,
            _ => return,
        };
        let target = shared_slot()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(shared) = target {
            shared.push(cmd);
        }
    }

    pub fn sync(shared: Arc<TrayShared>, enabled: bool, unlocked: bool) {
        *shared_slot()
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = if enabled { Some(shared) } else { None };
        let icon = crate::brand::ICON_PNG;
        unsafe {
            fp_macos_tray_sync(enabled, unlocked, icon.as_ptr(), icon.len(), tray_callback);
        }
    }

    pub fn disable() {
        *shared_slot()
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        unsafe {
            fp_macos_tray_sync(false, false, std::ptr::null(), 0, tray_callback);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation (via windows-sys Shell_NotifyIconW)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows_impl {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
    use std::thread::JoinHandle;

    use windows_sys::Win32::Foundation::{
        HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE,
        NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
        DispatchMessageW, GetCursorPos, GetMessageW, GetSystemMetrics, LoadIconW, LoadImageW,
        PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW,
        SetForegroundWindow, SetMenuDefaultItem, TrackPopupMenu, TranslateMessage, HICON,
        IDI_APPLICATION, IMAGE_ICON, LR_SHARED, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
        SM_CXSMICON, SM_CYSMICON, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_NONOTIFY, TPM_RETURNCMD,
        TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONDBLCLK, WM_NULL,
        WM_RBUTTONUP, WNDCLASSEXW, WS_OVERLAPPED,
    };

    use super::{TrayCommand, TrayShared};

    const WM_TRAY_ICON: u32 = WM_APP + 1;
    const TRAY_ICON_ID: u32 = 1;
    const NIN_KEYSELECT: u32 = NIN_SELECT + 1;

    const CMD_SHOW: usize = 1001;
    const CMD_LOCK: usize = 1002;
    const CMD_QUIT: usize = 1003;

    static ACTIVE_SHARED: OnceLock<Mutex<Option<Arc<TrayShared>>>> = OnceLock::new();
    static TASKBAR_CREATED_MSG: AtomicU32 = AtomicU32::new(0);

    fn shared_slot() -> &'static Mutex<Option<Arc<TrayShared>>> {
        ACTIVE_SHARED.get_or_init(|| Mutex::new(None))
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct WinTrayWorker {
        hwnd: isize,
        thread: Option<JoinHandle<()>>,
    }

    impl WinTrayWorker {
        pub fn stop(mut self) {
            if self.hwnd != 0 {
                unsafe {
                    PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0);
                }
            }
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
            *shared_slot()
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
        }
    }

    fn load_tray_icon(hinst: HINSTANCE) -> HICON {
        unsafe {
            // Resource ID 1 is embedded by build.rs (assets/app-icon.ico).
            let res_id = 1usize as *const u16;
            let icon = LoadImageW(
                hinst,
                res_id,
                IMAGE_ICON,
                GetSystemMetrics(SM_CXSMICON),
                GetSystemMetrics(SM_CYSMICON),
                LR_SHARED,
            );
            if !icon.is_null() {
                return icon as HICON;
            }
            LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
        }
    }

    fn make_nid(hwnd: HWND, hicon: HICON) -> NOTIFYICONDATAW {
        let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
        nid.uCallbackMessage = WM_TRAY_ICON;
        nid.hIcon = hicon;
        let tip = to_wide(crate::brand::NAME);
        let len = tip.len().min(nid.szTip.len());
        nid.szTip[..len].copy_from_slice(&tip[..len]);
        nid
    }

    unsafe fn add_tray_icon(hwnd: HWND, hinst: HINSTANCE) {
        let mut nid = make_nid(hwnd, load_tray_icon(hinst));
        if Shell_NotifyIconW(NIM_ADD, &nid) != 0 {
            nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            let _ = Shell_NotifyIconW(NIM_SETVERSION, &nid);
        }
    }

    unsafe fn remove_tray_icon(hwnd: HWND) {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_ICON_ID;
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let shared = shared_slot()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(shared) = shared else {
            return;
        };
        let unlocked = shared.unlocked.load(Ordering::Relaxed);

        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        let show_label = to_wide("Show friendlypass");
        let lock_label = to_wide("Lock Database");
        let quit_label = to_wide("Quit");

        AppendMenuW(menu, MF_STRING, CMD_SHOW, show_label.as_ptr());
        let lock_flags = if unlocked {
            MF_STRING
        } else {
            MF_STRING | MF_GRAYED
        };
        AppendMenuW(menu, lock_flags, CMD_LOCK, lock_label.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_QUIT, quit_label.as_ptr());
        SetMenuDefaultItem(menu, CMD_SHOW as u32, 0);

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // Required by MSDN so clicking outside the popup menu dismisses it.
        SetForegroundWindow(hwnd);
        let selected = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        ) as usize;
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);

        match selected {
            CMD_SHOW => shared.push(TrayCommand::Show),
            CMD_LOCK => shared.push(TrayCommand::Lock),
            CMD_QUIT => shared.push(TrayCommand::Quit),
            _ => {}
        }
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let taskbar_msg = TASKBAR_CREATED_MSG.load(Ordering::Relaxed);
        if taskbar_msg != 0 && msg == taskbar_msg {
            let hinst = GetModuleHandleW(std::ptr::null()) as HINSTANCE;
            add_tray_icon(hwnd, hinst);
            return 0;
        }
        match msg {
            WM_TRAY_ICON => {
                let event = (lparam as u32) & 0xFFFF;
                match event {
                    NIN_SELECT | NIN_KEYSELECT | WM_LBUTTONDBLCLK => {
                        if let Some(shared) = shared_slot()
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .clone()
                        {
                            shared.push(TrayCommand::Show);
                        }
                    }
                    WM_CONTEXTMENU | WM_RBUTTONUP => {
                        show_context_menu(hwnd);
                    }
                    _ => {}
                }
                0
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                remove_tray_icon(hwnd);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    pub fn start(shared: Arc<TrayShared>) -> Option<WinTrayWorker> {
        *shared_slot()
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(shared);

        let ready = Arc::new((Mutex::new(None::<isize>), Condvar::new()));
        let ready_bg = Arc::clone(&ready);

        let thread = std::thread::Builder::new()
            .name("friendlypass-tray".into())
            .spawn(move || unsafe {
                let hinst = GetModuleHandleW(std::ptr::null()) as HINSTANCE;
                let class_name = to_wide("FriendlyPassTrayWindowClass");
                let win_title = to_wide("friendlypass-tray");

                let wc = WNDCLASSEXW {
                    cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                    style: 0,
                    lpfnWndProc: Some(wnd_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinst,
                    hIcon: std::ptr::null_mut(),
                    hCursor: std::ptr::null_mut(),
                    hbrBackground: std::ptr::null_mut(),
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: class_name.as_ptr(),
                    hIconSm: std::ptr::null_mut(),
                };
                // Ignore failure if the class was already registered in this process.
                let _ = RegisterClassExW(&wc);

                let tb_msg = RegisterWindowMessageW(to_wide("TaskbarCreated").as_ptr());
                TASKBAR_CREATED_MSG.store(tb_msg, Ordering::Relaxed);

                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    win_title.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    hinst,
                    std::ptr::null(),
                );

                {
                    let (lock, cv) = &*ready_bg;
                    *lock.lock().unwrap_or_else(PoisonError::into_inner) = Some(hwnd as isize);
                    cv.notify_all();
                }

                if hwnd.is_null() {
                    return;
                }

                add_tray_icon(hwnd, hinst);

                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            })
            .ok()?;

        let (lock, cv) = &*ready;
        let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        while guard.is_none() {
            guard = cv.wait(guard).unwrap_or_else(PoisonError::into_inner);
        }
        let hwnd = guard.unwrap_or(0);
        if hwnd == 0 {
            let _ = thread.join();
            return None;
        }
        Some(WinTrayWorker {
            hwnd,
            thread: Some(thread),
        })
    }
}
