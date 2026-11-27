#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*FpTrayCallback)(int32_t action);

static const int32_t FP_TRAY_ACTION_SHOW = 1;
static const int32_t FP_TRAY_ACTION_LOCK = 2;
static const int32_t FP_TRAY_ACTION_QUIT = 3;

@interface FpTrayTarget : NSObject
@property (nonatomic, assign) FpTrayCallback callback;
@end

@implementation FpTrayTarget
- (void)onShow:(id)sender {
    (void)sender;
    if (self.callback) {
        self.callback(FP_TRAY_ACTION_SHOW);
    }
}
- (void)onLock:(id)sender {
    (void)sender;
    if (self.callback) {
        self.callback(FP_TRAY_ACTION_LOCK);
    }
}
- (void)onQuit:(id)sender {
    (void)sender;
    if (self.callback) {
        self.callback(FP_TRAY_ACTION_QUIT);
    }
}
@end

static NSStatusItem *g_status_item = nil;
static FpTrayTarget *g_tray_target = nil;
static NSMenuItem *g_lock_item = nil;

void fp_macos_tray_sync(
    bool enabled,
    bool unlocked,
    const uint8_t *icon_png,
    size_t icon_len,
    FpTrayCallback callback
) {
    NSData *iconData = (icon_png && icon_len > 0)
        ? [NSData dataWithBytes:icon_png length:icon_len]
        : nil;

    void (^work)(void) = ^{
        @autoreleasepool {
            if (!enabled) {
                if (g_status_item) {
                    [[NSStatusBar systemStatusBar] removeStatusItem:g_status_item];
                    g_status_item = nil;
                }
                g_lock_item = nil;
                g_tray_target = nil;
                return;
            }

            if (!g_status_item) {
                NSStatusItem *item = [[NSStatusBar systemStatusBar]
                    statusItemWithLength:NSSquareStatusItemLength];
                if (!item) {
                    return;
                }
                NSImage *image = nil;
                if (iconData) {
                    image = [[NSImage alloc] initWithData:iconData];
                }
                if (!image) {
                    image = [[NSApplication sharedApplication] applicationIconImage];
                }
                if (image) {
                    [image setSize:NSMakeSize(18.0, 18.0)];
                    item.button.image = image;
                } else {
                    item.button.title = @"fp";
                }
                item.button.toolTip = @"friendlypass";

                FpTrayTarget *target = [[FpTrayTarget alloc] init];
                target.callback = callback;

                NSMenu *menu = [[NSMenu alloc] initWithTitle:@"friendlypass"];
                menu.autoenablesItems = NO;

                NSMenuItem *showItem = [[NSMenuItem alloc]
                    initWithTitle:@"Show friendlypass"
                           action:@selector(onShow:)
                    keyEquivalent:@""];
                showItem.target = target;
                [menu addItem:showItem];

                NSMenuItem *lockItem = [[NSMenuItem alloc]
                    initWithTitle:@"Lock Database"
                           action:@selector(onLock:)
                    keyEquivalent:@""];
                lockItem.target = target;
                lockItem.enabled = unlocked;
                [menu addItem:lockItem];

                [menu addItem:[NSMenuItem separatorItem]];

                NSMenuItem *quitItem = [[NSMenuItem alloc]
                    initWithTitle:@"Quit friendlypass"
                           action:@selector(onQuit:)
                    keyEquivalent:@""];
                quitItem.target = target;
                [menu addItem:quitItem];

                item.menu = menu;
                g_status_item = item;
                g_tray_target = target;
                g_lock_item = lockItem;
            } else {
                if (g_tray_target) {
                    g_tray_target.callback = callback;
                }
                if (g_lock_item) {
                    g_lock_item.enabled = unlocked;
                }
            }
        }
    };

    if ([NSThread isMainThread]) {
        work();
    } else {
        dispatch_async(dispatch_get_main_queue(), work);
    }
}
