#import <AuthenticationServices/AuthenticationServices.h>
#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool copy_nsstring_to_buf(NSString *str, char *buf, size_t len) {
    if (!str || !buf || len == 0) {
        return false;
    }
    const char *utf8 = [str UTF8String];
    if (!utf8) {
        return false;
    }
    size_t n = strlen(utf8);
    if (n + 1 > len) {
        return false;
    }
    memcpy(buf, utf8, n + 1);
    return true;
}

/// Resolves the shared App Group directory from the app bundle's
/// `FPAppGroupIdentifier` Info.plist key.
///
/// Uses `containerURLForSecurityApplicationGroupIdentifier:` when entitled and
/// falls back to `~/Library/Group Containers/<groupId>` for unsandboxed hosts.
bool fp_macos_app_group_dir(char *buf, size_t len) {
    @autoreleasepool {
        @try {
            NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
            id raw = info[@"FPAppGroupIdentifier"];
            if (![raw isKindOfClass:[NSString class]]) {
                return false;
            }
            NSString *groupId = (NSString *)raw;
            if (groupId.length == 0) {
                return false;
            }
            NSURL *url = [[NSFileManager defaultManager]
                containerURLForSecurityApplicationGroupIdentifier:groupId];
            if (url && url.path.length > 0) {
                return copy_nsstring_to_buf(url.path, buf, len);
            }
            NSString *home = NSHomeDirectory();
            if (home.length == 0) {
                return false;
            }
            NSString *fallback = [[home stringByAppendingPathComponent:@"Library/Group Containers"]
                stringByAppendingPathComponent:groupId];
            return copy_nsstring_to_buf(fallback, buf, len);
        } @catch (NSException *exception) {
            (void)exception;
            return false;
        }
    }
}

/// Returns 1 when macOS reports the AutoFill Credential Provider store as
/// enabled for this app, 0 otherwise.
int fp_macos_credential_store_enabled(void) {
    @autoreleasepool {
        @try {
            if (@available(macOS 11.0, *)) {
                __block int enabled = 0;
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                [[ASCredentialIdentityStore sharedStore]
                    getCredentialIdentityStoreStateWithCompletion:^(
                        ASCredentialIdentityStoreState *state) {
                        enabled = state.isEnabled ? 1 : 0;
                        dispatch_semaphore_signal(sem);
                    }];
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
                return enabled;
            }
            return 0;
        } @catch (NSException *exception) {
            (void)exception;
            return 0;
        }
    }
}

/// Replaces all non-secret identities in `ASCredentialIdentityStore.sharedStore`
/// from a UTF-8 JSON object:
/// `{ "passkeys": [...], "passwords": [...], "totps": [...] }`.
///
/// Returns:
///   0 = synced successfully
///   1 = store disabled (no-op)
///  -1 = invalid input or OS error
int fp_macos_replace_credential_identities(const char *json_utf8) {
    if (!json_utf8) {
        return -1;
    }
    @autoreleasepool {
        @try {
            if (@available(macOS 14.0, *)) {
                NSData *data = [NSData dataWithBytes:json_utf8 length:strlen(json_utf8)];
                NSError *parseErr = nil;
                id parsed = [NSJSONSerialization JSONObjectWithData:data
                                                            options:0
                                                              error:&parseErr];
                if (parseErr || ![parsed isKindOfClass:[NSDictionary class]]) {
                    return -1;
                }
                NSDictionary *root = (NSDictionary *)parsed;

                __block BOOL isEnabled = NO;
                dispatch_semaphore_t stateSem = dispatch_semaphore_create(0);
                [[ASCredentialIdentityStore sharedStore]
                    getCredentialIdentityStoreStateWithCompletion:^(
                        ASCredentialIdentityStoreState *state) {
                        isEnabled = state.isEnabled;
                        dispatch_semaphore_signal(stateSem);
                    }];
                if (dispatch_semaphore_wait(
                        stateSem, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) != 0) {
                    return -1;
                }
                if (!isEnabled) {
                    return 1;
                }

                NSMutableArray<id<ASCredentialIdentity>> *identities = [NSMutableArray array];

                NSArray *passkeys = root[@"passkeys"];
                if ([passkeys isKindOfClass:[NSArray class]]) {
                    for (id item in passkeys) {
                        if (![item isKindOfClass:[NSDictionary class]]) continue;
                        NSDictionary *dict = (NSDictionary *)item;
                        NSString *rpId = dict[@"rp_id"];
                        NSString *username = dict[@"username"];
                        NSString *credB64 = dict[@"credential_id_b64"];
                        NSString *handleB64 = dict[@"user_handle_b64"];
                        NSString *uuid = dict[@"uuid"];
                        if (![rpId isKindOfClass:[NSString class]] || rpId.length == 0) continue;
                        if (![credB64 isKindOfClass:[NSString class]]) continue;
                        NSData *credId = [[NSData alloc] initWithBase64EncodedString:credB64 options:0];
                        if (!credId || credId.length == 0) continue;
                        NSData *userHandle = [NSData data];
                        if ([handleB64 isKindOfClass:[NSString class]] && handleB64.length > 0) {
                            NSData *decoded = [[NSData alloc] initWithBase64EncodedString:handleB64 options:0];
                            if (decoded) userHandle = decoded;
                        }
                        NSString *user = [username isKindOfClass:[NSString class]] ? username : @"";
                        NSString *recordId = [uuid isKindOfClass:[NSString class]] ? uuid : nil;
                        ASPasskeyCredentialIdentity *identity =
                            [ASPasskeyCredentialIdentity identityWithRelyingPartyIdentifier:rpId
                                                                                   userName:user
                                                                               credentialID:credId
                                                                                 userHandle:userHandle
                                                                           recordIdentifier:recordId];
                        if (identity) {
                            [identities addObject:identity];
                        }
                    }
                }

                NSArray *passwords = root[@"passwords"];
                if ([passwords isKindOfClass:[NSArray class]]) {
                    for (id item in passwords) {
                        if (![item isKindOfClass:[NSDictionary class]]) continue;
                        NSDictionary *dict = (NSDictionary *)item;
                        NSString *service = dict[@"service"];
                        NSString *username = dict[@"username"];
                        NSString *uuid = dict[@"uuid"];
                        NSNumber *isUrl = dict[@"is_url"];
                        if (![service isKindOfClass:[NSString class]] || service.length == 0) continue;
                        ASCredentialServiceIdentifierType kind =
                            ([isUrl isKindOfClass:[NSNumber class]] && isUrl.boolValue)
                                ? ASCredentialServiceIdentifierTypeURL
                                : ASCredentialServiceIdentifierTypeDomain;
                        ASCredentialServiceIdentifier *sid =
                            [[ASCredentialServiceIdentifier alloc] initWithIdentifier:service type:kind];
                        NSString *user = [username isKindOfClass:[NSString class]] ? username : @"";
                        NSString *recordId = [uuid isKindOfClass:[NSString class]] ? uuid : nil;
                        ASPasswordCredentialIdentity *identity =
                            [ASPasswordCredentialIdentity identityWithServiceIdentifier:sid
                                                                                   user:user
                                                                       recordIdentifier:recordId];
                        if (identity) {
                            [identities addObject:identity];
                        }
                    }
                }

                if (@available(macOS 15.0, *)) {
                    NSArray *totps = root[@"totps"];
                    if ([totps isKindOfClass:[NSArray class]]) {
                        for (id item in totps) {
                            if (![item isKindOfClass:[NSDictionary class]]) continue;
                            NSDictionary *dict = (NSDictionary *)item;
                            NSString *service = dict[@"service"];
                            NSString *label = dict[@"label"];
                            NSString *uuid = dict[@"uuid"];
                            NSNumber *isUrl = dict[@"is_url"];
                            if (![service isKindOfClass:[NSString class]] || service.length == 0) continue;
                            ASCredentialServiceIdentifierType kind =
                                ([isUrl isKindOfClass:[NSNumber class]] && isUrl.boolValue)
                                    ? ASCredentialServiceIdentifierTypeURL
                                    : ASCredentialServiceIdentifierTypeDomain;
                            ASCredentialServiceIdentifier *sid =
                                [[ASCredentialServiceIdentifier alloc] initWithIdentifier:service type:kind];
                            NSString *lbl = [label isKindOfClass:[NSString class]] ? label : @"";
                            NSString *recordId = [uuid isKindOfClass:[NSString class]] ? uuid : nil;
                            ASOneTimeCodeCredentialIdentity *identity =
                                [[ASOneTimeCodeCredentialIdentity alloc]
                                    initWithServiceIdentifier:sid
                                                        label:lbl
                                             recordIdentifier:recordId];
                            if (identity) {
                                [identities addObject:identity];
                            }
                        }
                    }
                }

                __block BOOL ok = NO;
                dispatch_semaphore_t saveSem = dispatch_semaphore_create(0);
                [[ASCredentialIdentityStore sharedStore]
                    replaceCredentialIdentityEntries:identities
                                          completion:^(BOOL success, NSError * _Nullable error) {
                                              (void)error;
                                              ok = success;
                                              dispatch_semaphore_signal(saveSem);
                                          }];
                if (dispatch_semaphore_wait(
                        saveSem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
                    return -1;
                }
                return ok ? 0 : -1;
            }
            return 1;
        } @catch (NSException *exception) {
            (void)exception;
            return -1;
        }
    }
}
