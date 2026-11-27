#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int32_t prev_pid;
    bool was_minimized;
    bool was_hidden;
    bool was_focused;
} FpMacosWindowSnapshot;

static bool g_has_pending_snapshot = false;
static FpMacosWindowSnapshot g_pending_snapshot = {0, false, false, false};

static void activate_app_ignoring_others(NSRunningApplication *app) {
    if (!app || app.terminated) {
        return;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [app activateWithOptions:NSApplicationActivateIgnoringOtherApps];
#pragma clang diagnostic pop
}

static FpMacosWindowSnapshot capture_and_activate_on_main(void) {
    FpMacosWindowSnapshot snap = {0, false, false, false};
    @autoreleasepool {
        pid_t selfPid = [[NSProcessInfo processInfo] processIdentifier];
        NSRunningApplication *front = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (front && front.processIdentifier > 0 && front.processIdentifier != selfPid) {
            snap.prev_pid = (int32_t)front.processIdentifier;
            snap.was_focused = false;
        } else {
            snap.was_focused = true;
        }

        NSApplication *app = [NSApplication sharedApplication];
        if (!app) {
            return snap;
        }

        BOOL anyMainWindow = NO;
        BOOL anyVisible = NO;
        BOOL anyMiniaturized = NO;
        for (NSWindow *win in [app windows]) {
            // Skip status bar windows / helper panels; inspect only main app windows.
            if (![win canBecomeMainWindow]) {
                continue;
            }
            anyMainWindow = YES;
            if ([win isMiniaturized]) {
                anyMiniaturized = YES;
            }
            if ([win isVisible] && ![win isMiniaturized]) {
                anyVisible = YES;
            }
        }
        snap.was_minimized = (anyMiniaturized && !anyVisible) || [app isHidden];
        snap.was_hidden = anyMainWindow && !anyVisible && !anyMiniaturized && ![app isHidden];

        [app unhide:nil];
        for (NSWindow *win in [app windows]) {
            if (![win canBecomeMainWindow]) {
                continue;
            }
            if ([win isMiniaturized]) {
                [win deminiaturize:nil];
            }
            [win makeKeyAndOrderFront:nil];
        }
        if ([app respondsToSelector:@selector(activate)]) {
            [app performSelector:@selector(activate)];
        }
        activate_app_ignoring_others([NSRunningApplication currentApplication]);
    }
    return snap;
}

/// Schedules unminimize/unhide/activate on the macOS main queue without
/// blocking the caller. Stores the pre-activation snapshot so the GUI thread
/// can restore focus to the previous app once the prompt finishes.
void fp_macos_wake_from_background(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        FpMacosWindowSnapshot snap = capture_and_activate_on_main();
        if (!g_has_pending_snapshot) {
            g_pending_snapshot = snap;
            g_has_pending_snapshot = true;
        }
    });
}

/// Shows and activates the main application window (used when restoring from
/// the menu bar status item).
void fp_macos_show_main_window(void) {
    void (^work)(void) = ^{
        g_has_pending_snapshot = false;
        (void)capture_and_activate_on_main();
    };
    if ([NSThread isMainThread]) {
        work();
    } else {
        dispatch_async(dispatch_get_main_queue(), work);
    }
}

/// Called on the GUI (main) thread when a confirmation prompt becomes active.
/// Consumes any snapshot captured by `fp_macos_wake_from_background`, or
/// captures and activates immediately if not already woken.
void fp_macos_activate_for_prompt(
    int32_t *out_prev_pid,
    bool *out_was_minimized,
    bool *out_was_hidden,
    bool *out_was_focused
) {
    FpMacosWindowSnapshot snap = {0, false, false, false};
    if ([NSThread isMainThread]) {
        if (g_has_pending_snapshot) {
            snap = g_pending_snapshot;
            g_has_pending_snapshot = false;
            // Ensure app is still frontmost.
            (void)capture_and_activate_on_main();
        } else {
            snap = capture_and_activate_on_main();
        }
    }
    if (out_prev_pid) *out_prev_pid = snap.prev_pid;
    if (out_was_minimized) *out_was_minimized = snap.was_minimized;
    if (out_was_hidden) *out_was_hidden = snap.was_hidden;
    if (out_was_focused) *out_was_focused = snap.was_focused;
}

/// Returns focus to a previously active application (e.g. Chrome/Firefox)
/// after a confirmation prompt is completed or cancelled.
void fp_macos_restore_app_pid(int32_t pid) {
    if (pid <= 0) {
        return;
    }
    void (^work)(void) = ^{
        @autoreleasepool {
            g_has_pending_snapshot = false;
            pid_t selfPid = [[NSProcessInfo processInfo] processIdentifier];
            if (pid == (int32_t)selfPid) {
                return;
            }
            NSRunningApplication *prev =
                [NSRunningApplication runningApplicationWithProcessIdentifier:(pid_t)pid];
            if (prev && !prev.terminated) {
                activate_app_ignoring_others(prev);
            }
        }
    };
    if ([NSThread isMainThread]) {
        work();
    } else {
        dispatch_async(dispatch_get_main_queue(), work);
    }
}
