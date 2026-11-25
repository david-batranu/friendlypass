# friendlypass Android — frozen contract (v1)

Read this before writing code. It is frozen: implement exactly your part. If something here is impossible, implement
the closest working thing and explain it in your report; do not silently change the shapes below.

## Environment (every agent)
```sh
export PATH=/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH      # rustup toolchain with Android targets + cargo-ndk
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
```
Rust targets installed: aarch64-linux-android, x86_64-linux-android. SDK platforms 34/35/36, build-tools 36.1.0.
AVDs: `Pixel_9a` (API 36, Play image), `api30`. Android app id / Kotlin root package: `org.friendlypass.android`.
Disk is limited (~20 GB free): no release builds unless needed, never `cargo clean` / delete caches outside your worktree.

## Layout
```
crates/friendlypass/src/matching.rs     URL + Android-app matching (pure, shared by browser + mobile)
crates/friendlypass-mobile/             UniFFI cdylib "friendlypass_mobile" (Vault API below)
crates/friendlypass-passkey/            WebAuthn authenticator + KeePassXC KPEX_PASSKEY_* storage
android/                                Gradle project (settings.gradle.kts, gradle wrapper, app/)
android/app/src/main/java/org/friendlypass/android/
  FriendlypassApp.kt                    Application; holds the singletons below
  vault/model/*.kt                      Kotlin domain model (below)
  vault/VaultRepository.kt              interface (below)
  vault/FakeVaultRepository.kt          in-memory impl used until the real one lands, and by tests
  vault/RustVaultRepository.kt          (wave 2) UniFFI-backed impl
  storage/DatabaseStore.kt              interface + SafDatabaseStore (SAF)
  unlock/                               UnlockGate composable, biometric wrapping
  ui/                                   browse/search/detail/settings screens
  autofill/                             (wave 2) AutofillService + auth activity
  credentials/                          (wave 2) CredentialProviderService + activities
```

## Rust: `friendlypass::matching` (pure functions)
```rust
pub struct MatchTarget<'a> { pub web_url: Option<&'a str>, pub android_package: Option<&'a str> }
/// Inputs per entry: main URL, additional URLs (KP2A_URL*, and any field whose value is androidapp://…),
/// AndroidApp* fields (KeePassDX convention: "AndroidApp", "AndroidApp_1", …).
pub struct MatchCandidate<'a> { pub url: &'a str, pub additional_urls: &'a [String], pub android_apps: &'a [String] }
/// Lower is better; None = no match. Web scoring is exactly today's browser `entry_match_score` (move it, don't fork it).
/// Android: exact package match against android_apps or an `androidapp://<pkg>` URL scores 0.
pub fn score(c: &MatchCandidate, t: &MatchTarget) -> Option<u16>;
```
`crates/friendlypass-browser/src/service.rs` must call this module; all existing browser tests stay green.

## Rust: `friendlypass-mobile` UniFFI surface (proc-macro UniFFI, crate name `friendlypass_mobile`)
```rust
#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum VaultError { InvalidCredentials, Corrupt { msg: String }, Unsupported { msg: String }, NotFound, Io { msg: String } }

#[derive(uniffi::Record)] pub struct EntrySummary { pub uuid: String /*dashless lowercase hex*/, pub title: String,
    pub username: String, pub url: String, pub group_path: String /*"Root/Email"*/, pub has_totp: bool, pub has_passkey: bool }
#[derive(uniffi::Record)] pub struct EntryField { pub name: String, pub value: String, pub protected: bool }
#[derive(uniffi::Record)] pub struct EntryDetail { pub summary: EntrySummary, pub password: String, pub notes: String,
    pub urls: Vec<String> /*main first*/, pub android_apps: Vec<String>, pub custom_fields: Vec<EntryField>,
    pub tags: Vec<String> }
#[derive(uniffi::Record)] pub struct GroupNode { pub uuid: String, pub name: String, pub parent_uuid: Option<String>,
    pub entry_count: u32 }
#[derive(uniffi::Record)] pub struct TotpCode { pub code: String, pub period_secs: u32, pub remaining_secs: u32 }
#[derive(uniffi::Record)] pub struct NewLogin { pub title: String, pub username: String, pub password: String,
    pub url: Option<String>, pub android_app: Option<String> }

#[uniffi::export] pub fn open_vault(kdbx: Vec<u8>, password: Option<String>, keyfile: Option<Vec<u8>>)
    -> Result<Arc<Vault>, VaultError>;
#[uniffi::export] impl Vault {
  pub fn database_name(&self) -> String;
  pub fn root_group_uuid(&self) -> String;
  pub fn groups(&self) -> Vec<GroupNode>;                         // recycle bin excluded
  pub fn entries_in_group(&self, group_uuid: String) -> Vec<EntrySummary>;
  pub fn all_entries(&self) -> Vec<EntrySummary>;                 // recycle bin excluded
  pub fn search(&self, query: String) -> Vec<EntrySummary>;       // case-insensitive title/username/url/notes/tags
  pub fn entry(&self, uuid: String) -> Result<EntryDetail, VaultError>;
  pub fn totp(&self, uuid: String, unix_secs: u64) -> Option<TotpCode>;
  pub fn match_web(&self, url: String) -> Vec<EntrySummary>;      // sorted best first
  pub fn match_app(&self, package: String) -> Vec<EntrySummary>;
  pub fn add_login(&self, login: NewLogin) -> Result<String, VaultError>;  // returns new uuid; android_app → "AndroidApp" field
  pub fn is_modified(&self) -> bool;
  pub fn save(&self) -> Result<Vec<u8>, VaultError>;              // KDBX4 bytes, same credentials as opened
  // wave 2 (added by M6, backed by friendlypass-passkey):
  pub fn passkeys_for_rp(&self, rp_id: String, allow_credential_ids: Vec<Vec<u8>>) -> Vec<PasskeyInfo>;
  pub fn register_passkey(&self, req: PasskeyCreateRequest) -> Result<PasskeyRegistration, VaultError>;
  pub fn assert_passkey(&self, entry_uuid: String, rp_id: String, client_data_hash: Vec<u8>) -> Result<PasskeyAssertion, VaultError>;
}
```
`Vault` uses interior mutability (`Mutex`). Passwords/keyfiles are zeroized after use; nothing is logged.

## Rust: `friendlypass-passkey` (no keepass dependency; works on a field map)
Storage = KeePassXC format exactly (verify against ../keepassxc/src/browser/BrowserPasskeys.cpp, BrowserService.cpp,
PasskeyUtils.cpp, core/EntryAttributes.cpp): KPEX_PASSKEY_USERNAME, KPEX_PASSKEY_CREDENTIAL_ID (base64url, protected),
KPEX_PASSKEY_PRIVATE_KEY_PEM (PKCS#8 PEM, protected), KPEX_PASSKEY_RELYING_PARTY, KPEX_PASSKEY_USER_HANDLE
(base64url, protected), KPEX_PASSKEY_FLAG_BE="1", KPEX_PASSKEY_FLAG_BS="1". Signature counter always 0, as KeePassXC.
AAGUID: all zeros. Attestation format "none".
```rust
pub struct StoredPasskey { pub credential_id: Vec<u8>, pub private_key_pem: String, pub rp_id: String,
    pub username: String, pub user_handle: Vec<u8>, pub backup_eligible: bool, pub backup_state: bool }
pub struct PasskeyField { pub name: &'static str, pub value: String, pub protected: bool }
impl StoredPasskey {
  pub fn from_fields(get: impl Fn(&str) -> Option<String>) -> Option<StoredPasskey>;
  pub fn to_fields(&self) -> Vec<PasskeyField>;
}
pub const ES256: i64 = -7; pub const EDDSA: i64 = -8; pub const RS256: i64 = -257;
pub struct Registration { pub passkey: StoredPasskey, pub credential_id: Vec<u8>, pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>, pub public_key_cose: Vec<u8>, pub public_key_spki_der: Vec<u8>, pub algorithm: i64 }
pub struct Assertion { pub credential_id: Vec<u8>, pub authenticator_data: Vec<u8>, pub signature: Vec<u8>,
    pub user_handle: Vec<u8> }
/// Picks the first supported alg from `algorithms` (ES256 if empty). Flags UP|UV|AT|BE|BS.
pub fn register(rp_id: &str, username: &str, user_handle: &[u8], algorithms: &[i64]) -> Result<Registration, PasskeyError>;
/// authData = sha256(rp_id) | flags UP|UV|BE|BS | counter 0; signature over authData || client_data_hash (DER for ES256).
pub fn assert(p: &StoredPasskey, client_data_hash: &[u8]) -> Result<Assertion, PasskeyError>;
/// {"type":kind,"challenge":b64url(challenge),"origin":origin,"crossOrigin":false[,"androidPackageName":pkg]}
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str, android_package: Option<&str>) -> String;
pub fn b64url_encode(b: &[u8]) -> String; pub fn b64url_decode(s: &str) -> Result<Vec<u8>, PasskeyError>;
```
Mobile mirror records (wave 2): `PasskeyInfo { entry_uuid, credential_id: Vec<u8>, rp_id, username, user_handle: Vec<u8> }`,
`PasskeyCreateRequest { rp_id, rp_name, user_name, user_display_name, user_handle: Vec<u8>, algorithms: Vec<i64>,
exclude_credential_ids: Vec<Vec<u8>> }` (register creates a new entry titled rp_id, username = user_name),
`PasskeyRegistration { entry_uuid, credential_id, authenticator_data, attestation_object, public_key_spki_der, algorithm }`,
`PasskeyAssertion { credential_id, authenticator_data, signature, user_handle }`.

## Kotlin domain model (`org.friendlypass.android.vault.model`)
Plain data classes mirroring the Rust records with Kotlin names: `EntrySummary`, `EntryField`, `EntryDetail`,
`GroupNode`, `TotpCode`, `NewLogin`, `PasskeyInfo`, `PasskeyCreateRequest`, `PasskeyRegistration`, `PasskeyAssertion`
(same fields, camelCase, `ByteArray` for bytes, `Long` for i64/u64, `Int` for u32). Plus:
```kotlin
data class DatabaseRef(val uri: String, val displayName: String)          // persisted SAF URI
sealed interface VaultState {
  data object NoDatabase : VaultState
  data class Locked(val db: DatabaseRef) : VaultState
  data class Unlocked(val db: DatabaseRef, val databaseName: String) : VaultState
}
sealed class VaultException(msg: String) : Exception(msg) {
  class InvalidCredentials : VaultException("Wrong password or key file")
  class Locked : VaultException("Database is locked")
  class Conflict : VaultException("Database changed elsewhere and could not be merged")
  class Failure(msg: String) : VaultException(msg)
}
```

## Kotlin `VaultRepository` (`org.friendlypass.android.vault`)
```kotlin
interface VaultRepository {
  val state: StateFlow<VaultState>
  fun selectDatabase(db: DatabaseRef)                     // → Locked(db); remembers as current
  suspend fun unlock(password: CharArray?, keyfile: ByteArray?)   // throws VaultException; wipes inputs
  fun lock()                                              // drop the vault; → Locked
  fun groups(): List<GroupNode>; fun rootGroupUuid(): String
  fun entriesInGroup(groupUuid: String): List<EntrySummary>
  fun search(query: String): List<EntrySummary>
  fun entry(uuid: String): EntryDetail
  fun totp(uuid: String, nowSecs: Long = System.currentTimeMillis() / 1000): TotpCode?
  fun matchWeb(url: String): List<EntrySummary>
  fun matchApp(packageName: String): List<EntrySummary>
  suspend fun addLogin(login: NewLogin): String           // adds + saves through DatabaseStore (conflict-safe)
  fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo>
  suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration   // adds + saves
  fun assertPasskey(entryUuid: String, rpId: String, clientDataHash: ByteArray): PasskeyAssertion
}
```
All read methods throw `VaultException.Locked` when not unlocked. Auto-lock (timeout, screen off) lives in the app layer
and calls `lock()`.

## Kotlin `DatabaseStore` (`org.friendlypass.android.storage`)
```kotlin
data class Snapshot(val bytes: ByteArray, val lastModified: Long?, val size: Long?)
sealed interface WriteResult { data class Written(val snapshot: Snapshot) : WriteResult; data object Conflict : WriteResult }
interface DatabaseStore {
  fun recent(): List<DatabaseRef>; fun remember(db: DatabaseRef); fun forget(db: DatabaseRef)
  suspend fun read(db: DatabaseRef): Snapshot             // provider first; offline → app-private cached copy
  suspend fun write(db: DatabaseRef, bytes: ByteArray, expected: Snapshot): WriteResult  // Conflict if remote metadata changed
}
```
Save algorithm (RustVaultRepository): write; on Conflict → `read` fresh, `open_vault` with the same credentials,
re-apply this session's pending additions (logins/passkeys), `save`, write again (max 3 tries) → else
`VaultException.Conflict`.

## UI hooks other packages use
- `FriendlypassApp.vault: VaultRepository`, `FriendlypassApp.store: DatabaseStore` (singletons; wave 2 swaps the
  vault to RustVaultRepository in ONE line).
- `@Composable fun UnlockGate(onUnlocked: () -> Unit, onCancel: () -> Unit)` in `unlock/`: shows the database picker
  if `NoDatabase`, the unlock screen (password, key file via SAF, biometric button when enrolled) if `Locked`, and
  calls `onUnlocked` immediately if already `Unlocked`. Autofill and credential activities host it.
- Biometric: `BiometricUnlock` in `unlock/` stores password+keyfile per DatabaseRef encrypted with an AndroidKeyStore
  AES-256-GCM key (user-auth required, invalidated by new enrollment); `BiometricPrompt` + `CryptoObject` decrypts.
- `ui/EntryPicker` composable: search list returning an EntrySummary (used by "Search friendlypass…" autofill chip).

## Gradle (android/)
Kotlin DSL, version catalog `gradle/libs.versions.toml`, AGP + Kotlin + Compose BOM at the newest stable versions
that resolve. minSdk 30, compile/target 36. Dependencies declared up front by the skeleton (so later agents don't
touch build files): compose (material3, navigation), lifecycle, coroutines, androidx.biometric,
androidx.autofill (inline suggestions UI), androidx.credentials + androidx.credentials provider APIs,
androidx.documentfile, net.java.dev.jna:jna@aar (UniFFI), junit + kotlinx-coroutines-test + robolectric (JVM tests),
androidx.test + espresso + uiautomator (instrumented). Wave 2 adds a `cargoNdkBuild` task (cargo-ndk →
app/src/main/jniLibs, uniffi-bindgen → build/generated/uniffi) wired before compile.

## Security baseline
`allowBackup=false` + data-extraction rules excluding everything; `FLAG_SECURE` on unlock/detail screens; clipboard
copies of secrets use `ClipDescription.EXTRA_IS_SENSITIVE` and auto-clear after 30 s; no INTERNET permission.
