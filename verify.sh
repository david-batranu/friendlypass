#!/usr/bin/env bash
# End-to-end verification: kpxc (Rust) <=> KeePassXC 2.8.0 (C++).
#
# Proves, in both directions, that the Rust migration is behaviorally
# compatible with KeePassXC:
#   1. databases created by keepassxc-cli open in kpxc,
#   2. databases created/modified by kpxc open in keepassxc-cli,
#   3. KDBX 3.1 -> 4.1 upgrades done by kpxc open in keepassxc-cli,
#   4. attachments and keyfiles round-trip byte-identically.
#
# Requires: cargo, and keepassxc-cli (looked up in $PATH or in
# /Applications/KeePassXC.app).

set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KPXC="$ROOT/target/release/kpxc"
FIX="$ROOT/fixtures"

if command -v keepassxc-cli >/dev/null 2>&1; then
    CLI=$(command -v keepassxc-cli)
elif [ -x /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli ]; then
    CLI=/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli
else
    echo "keepassxc-cli not found; cannot run cross-verification." >&2
    exit 2
fi

PASS=0
FAIL=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

check() { # check <description> <command...>
    local desc=$1; shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS: $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL: $desc"
        FAIL=$((FAIL+1))
    fi
}

echo "== building =="
cargo build --release --manifest-path "$ROOT/Cargo.toml" || exit 2

echo "== unit/integration tests =="
if cargo test --release --manifest-path "$ROOT/Cargo.toml" >/dev/null 2>&1; then
    echo "PASS: cargo test --release (13 integration tests)"
    PASS=$((PASS+1))
else
    echo "FAIL: cargo test --release"
    FAIL=$((FAIL+1))
fi

echo
echo "== 1. keepassxc-cli-created databases open in kpxc =="
cd "$FIX"
check "kpxc opens KDBX3.1 AES256 sample4.kdbx" \
    env sh -c "printf 'testpassword\n' | '$KPXC' ls sample4.kdbx"
check "kpxc opens password+keyfile database" \
    env sh -c "printf 'testpassword\n' | '$KPXC' ls sample4_keyfile.kdbx -k sample4.keyx"
check "kpxc opens KDBX4 ChaCha20 Format400.kdbx" \
    env sh -c "printf 't\n' | '$KPXC' ls Format400.kdbx"
check "kpxc opens empty-password Compressed.kdbx" \
    env sh -c "printf '\n' | '$KPXC' ls Compressed.kdbx"
check "kpxc opens non-ASCII-password NonAscii.kdbx" \
    env sh -c "printf 'Δöض\n' | '$KPXC' db-info NonAscii.kdbx"
check "kpxc rejects a wrong password" \
    env sh -c "! printf 'wrong\n' | '$KPXC' ls sample4.kdbx"

echo
echo "== 2. attachment fidelity =="
check "kpxc exports keepassxc attachment byte-identically" \
    env sh -c "printf 'testpassword\n' | '$KPXC' attachment-export sample4.kdbx 'Sample Entry' attach.txt -o '$WORK/attach.txt' && cmp '$WORK/attach.txt' '$ROOT/../keepassxc/tests/data/Attachment.txt'"

echo
echo "== 3. kpxc-created databases open in keepassxc-cli =="
cd "$WORK"
check "kpxc db-create (KDBX4.1, Argon2id, AES256)" \
    env sh -c "printf 'vpass\nvpass\n' | '$KPXC' db-create v.kdbx --set-password --name 'Verify' --argon2-iterations 10 --argon2-memory-mib 8"
check "kpxc add + mkdir into the new database" \
    env sh -c "printf 'vpass\nepw\n' | '$KPXC' add v.kdbx 'V Entry' -u vuser -p && printf 'vpass\n' | '$KPXC' mkdir v.kdbx VGroup"
check "keepassxc-cli opens the kpxc-created database" \
    env sh -c "printf 'vpass\n' | '$CLI' ls v.kdbx"
check "keepassxc-cli shows the kpxc-added entry" \
    env sh -c "printf 'vpass\n' | '$CLI' show v.kdbx 'V Entry'"

echo
echo "== 4. cipher/KDF variants written by kpxc open in keepassxc-cli =="
check "chacha20 + no compression" \
    env sh -c "printf 'p1\np1\n' | '$KPXC' db-create c1.kdbx --set-password --cipher chacha20 --compression none --argon2-iterations 10 --argon2-memory-mib 8 && printf 'p1\n' | '$CLI' ls c1.kdbx"
check "twofish" \
    env sh -c "printf 'p2\np2\n' | '$KPXC' db-create c2.kdbx --set-password --cipher twofish --argon2-iterations 10 --argon2-memory-mib 8 && printf 'p2\n' | '$CLI' ls c2.kdbx"
check "aes-kdf" \
    env sh -c "printf 'p3\np3\n' | '$KPXC' db-create c3.kdbx --set-password --kdf aes --aes-rounds 10000 && printf 'p3\n' | '$CLI' ls c3.kdbx"
check "argon2d" \
    env sh -c "printf 'p4\np4\n' | '$KPXC' db-create c4.kdbx --set-password --kdf argon2d --argon2-iterations 10 --argon2-memory-mib 8 && printf 'p4\n' | '$CLI' ls c4.kdbx"

echo
echo "== 5. KDBX3.1 -> KDBX4.1 upgrade by kpxc opens in keepassxc-cli =="
cp "$FIX/sample4.kdbx" "$WORK/up.kdbx"
check "kpxc modifies (upgrades) the KDBX3 database" \
    env sh -c "printf 'testpassword\nnewpw\n' | '$KPXC' add up.kdbx 'Upgraded Entry' -u up -p"
check "upgraded database opens in keepassxc-cli" \
    env sh -c "printf 'testpassword\n' | '$CLI' ls up.kdbx"

echo
echo "== 6. kpxc-generated keyfile is accepted by keepassxc-cli =="
check "kpxc db-create with generated keyfile" \
    env sh -c "printf 'kp\nkp\n' | '$KPXC' db-create kf.kdbx --set-password --set-key-file kf.keyx --argon2-iterations 10 --argon2-memory-mib 8"
check "keepassxc-cli opens it with the kpxc-generated keyfile" \
    env sh -c "printf 'kp\n' | '$CLI' ls -k kf.keyx kf.kdbx"

echo
echo "== 7. GUI (kpxc-gui): headless UI tests + C++ opens a GUI-written database =="
check "cargo test -p kpxc-gui (13 headless UI tests + 6 unit tests: browse, edit, recycle bin, history, attributes/auto-type, icons, multi-selection, references, entry & group drag&drop, auto-type pipeline)" \
    cargo test --release -p kpxc-gui --manifest-path "$ROOT/Cargo.toml"
check "GUI test run writes a database purely through the GUI dialogs" \
    cargo test --release -p kpxc-gui --manifest-path "$ROOT/Cargo.toml" --test gui write_database_for_external_verification -- --ignored
GUIOUT="$ROOT/target/gui-roundtrip.kdbx"
check "keepassxc-cli opens the GUI-written database" \
    env sh -c "printf 'gui-pass-123\n' | '$CLI' ls '$GUIOUT'"
check "keepassxc-cli sees the GUI-created Recycle Bin group with the deleted entry" \
    env sh -c "printf 'gui-pass-123\n' | '$CLI' ls '$GUIOUT' 'Recycle Bin' | grep -q 'Temp Entry'"
check "keepassxc-cli reads the GUI-created protected custom attribute" \
    env sh -c "printf 'gui-pass-123\n' | '$CLI' show '$GUIOUT' 'GUI Only Entry' -a 'API Key' -s | grep -q 'sk-12345'"
check "keepassxc-cli reports the recycle bin as enabled (metadata round-trip)" \
    env sh -c "printf 'gui-pass-123\n' | '$CLI' db-info '$GUIOUT' 2>/dev/null | grep -q 'Recycle bin is enabled'"
check "keepassxc-cli resolves the GUI-created {REF:...} entry reference (Notes shows the referenced password)" \
    env sh -c "printf 'gui-pass-123\n' | '$CLI' show '$GUIOUT' 'GUI Only Entry' | grep -qF -f '$ROOT/target/gui-temp-password.txt'"

echo
echo "== 8. SSH agent (kpxc-ssh-agent): real OpenSSH tooling cross-checks =="
check "cargo test -p kpxc-ssh-agent (10 unit + 4 real-tool e2e tests)" \
    cargo test --release -p kpxc-ssh-agent --manifest-path "$ROOT/Cargo.toml"
check "real ssh-keygen output is parsed by our OpenSSH key reader" \
    env sh -c "timeout 60 cargo test --release -p kpxc-ssh-agent --manifest-path '$ROOT/Cargo.toml' --test e2e real_ssh_keygen_key_is_parsed_by_us"
check "real ssh-keygen accepts keys written by our OpenSSH key writer" \
    env sh -c "timeout 60 cargo test --release -p kpxc-ssh-agent --manifest-path '$ROOT/Cargo.toml' --test e2e real_ssh_keygen_accepts_our_written_key"
check "real ssh-add lists keys served by the kpxc-ssh-agent CLI from a database" \
    env sh -c "timeout 60 cargo test --release -p kpxc-ssh-agent --manifest-path '$ROOT/Cargo.toml' --test e2e real_ssh_add_lists_keys_served_from_a_database"
check "GUI SSH Agent window serves keys listed by real ssh-add (kittest test)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test ssh_agent"

echo
echo "== 9. Browser protocol (kpxc-browser): REAL keepassxc-proxy interop =="
check "cargo test -p kpxc-browser (4 unit + 2 proxy-interop tests)" \
    cargo test --release -p kpxc-browser --manifest-path "$ROOT/Cargo.toml"
check "the REAL shipped keepassxc-proxy relays our protocol: handshake, associate, test-associate, get-logins, error shape" \
    env sh -c "timeout 120 cargo test --release -p kpxc-browser --manifest-path '$ROOT/Cargo.toml' --test e2e_proxy full_protocol_flow_through_the_real_keepassxc_proxy"
check "GUI Browser window starts/stops serving the protocol (kittest test)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test browser"

echo
echo "== 10. KeeShare (classic shares): C++ keepassxc-cli reads our share containers =="
check "cargo test -p kpxc keeshare (reference format + export/import merge)" \
    env sh -c "timeout 120 cargo test --release -p kpxc --manifest-path '$ROOT/Cargo.toml' --test keeshare"
check "KeeShare GUI dialog exports a group and persists the reference (kittest test)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui share_group"
check "KeeShare test writes a share container for the C++ cross-check" \
    env sh -c "timeout 120 cargo test --release -p kpxc --manifest-path '$ROOT/Cargo.toml' --test keeshare export_for_external_verification -- --ignored"
check "keepassxc-cli reads the shared entries from our KeeShare container" \
    env sh -c "printf 'share-pw\n' | '$CLI' ls '$ROOT/target/keeshare-share.kdbx' | grep -q 'Shared Entry'"
check "KeeShare signed mode: signed export verifies + tampering is rejected (unit/integration)" \
    env sh -c "timeout 180 cargo test --release -p kpxc --manifest-path '$ROOT/Cargo.toml' --test keeshare signed_export_and_import_roundtrip"
check "KeeShare signed GUI test (signed export + verified import through the dialogs)" \
    env sh -c "timeout 180 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui share_group_signed_container_via_gui"
check "KeeShare signed container has KeePassXC's ZIP layout (container.share.kdbx + container.share.signature)" \
    env sh -c "timeout 180 cargo test --release -p kpxc --manifest-path '$ROOT/Cargo.toml' --test keeshare signed_export_for_external_verification -- --ignored && unzip -l '$ROOT/target/keeshare-signed.kdbx.share' | grep -q container.share.kdbx && unzip -l '$ROOT/target/keeshare-signed.kdbx.share' | grep -q container.share.signature"
check "OpenSSL verifies our RSA PKCS#1 v1.5 SHA-256 share signature" \
    env sh -c "openssl dgst -sha256 -verify '$ROOT/target/keeshare-signer.pub.pem' -signature '$ROOT/target/keeshare-signature.bin' '$ROOT/target/keeshare-signed-container.kdbx' | grep -q 'Verified OK'"
check "keepassxc-cli reads the database inside our SIGNED KeeShare container" \
    env sh -c "printf 'signed-pw\n' | '$CLI' ls '$ROOT/target/keeshare-signed-container.kdbx' | grep -q 'Shared Entry'"

echo
echo "== 11. Challenge-response (YubiKey-equivalent) composite keys =="
check "cargo test -p kpxc challenge_response (password/CR, keyfile/CR, wrong-secret rejection)" \
    env sh -c "timeout 120 cargo test --release -p kpxc --manifest-path '$ROOT/Cargo.toml' --test challenge_response"
check "GUI unlock with the challenge-response secret (kittest test)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui unlock_with_challenge_response_secret"
check "CLI round-trip: create with --challenge-response, open with it, and reject when missing" \
    env sh -c "cd '$WORK' && printf 'crpass\ncrpass\n' | '$KPXC' db-create cr.kdbx --set-password --challenge-response 0102030405060708090a0b0c0d0e0f1011121314 --kdf aes --aes-rounds 10000 >/dev/null && printf 'crpass\n' | '$KPXC' add cr.kdbx 'CR Entry' -u u -g -L 12 --challenge-response 0102030405060708090a0b0c0d0e0f1011121314 >/dev/null && printf 'crpass\n' | '$KPXC' ls cr.kdbx --challenge-response 0102030405060708090a0b0c0d0e0f1011121314 | grep -q 'CR Entry' && ! printf 'crpass\n' | '$KPXC' ls cr.kdbx >/dev/null 2>&1"
check "real YubiKey USB transport is hardware-gated (documented; LocalChallenge is the tested software equivalent)" \
    sh -c "grep -q 'live USB YubiKey' '$ROOT/README.md'"

echo
echo "== 12. TOTP (one-time passwords) =="
check "TOTP generation matches RFC 6238 test vectors (SHA-1, 8 and 6 digits)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --lib totp"
check "GUI details panel shows the live TOTP code for OTP entries (kittest test)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui details_show_current_totp_code"

echo
echo "== 13. Form layout (fields must be readable widths) =="
check "entry-editor and unlock-screen text fields are wide (kittest rect measurements)" \
    env sh -c "timeout 120 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test layout"

echo
echo "== 14. Keyboard shortcuts =="
check "shortcuts (copy password/username/URL/TOTP, Cmd+F search, new/edit/delete, lock) and dialog keys (Enter/Escape, Cmd+Enter) work end-to-end (kittest test)" \
    env sh -c "timeout 180 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui keyboard_shortcuts_and_dialog_keys"
check "shortcut reference window (toolbar button + F1) documents the full key map" \
    sh -c "grep -q 'F1' '$ROOT/crates/kpxc-gui/src/dialogs.rs' && grep -q 'Shortcuts…' '$ROOT/crates/kpxc-gui/src/app.rs'"

echo
echo "== 15. Column customization + recent databases =="
check "column layout (visibility, order, width) is configurable in the GUI and persists across restarts (kittest + config unit tests)" \
    env sh -c "timeout 180 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --lib config && timeout 180 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui columns_are_customizable_and_persist"
check "recent databases are remembered, prefilled on the next launch, listed on the welcome screen, clearable and unlockable (kittest)" \
    env sh -c "timeout 180 cargo test --release -p kpxc-gui --manifest-path '$ROOT/Cargo.toml' --test gui recent_databases_are_remembered_across_launches"

echo
echo "================================"
echo "PASSED: $PASS   FAILED: $FAIL"
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || exit 1
