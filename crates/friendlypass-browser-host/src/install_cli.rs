//! `--install` / `--uninstall`: the command-line face of
//! [`friendlypass_browser::native_messaging`].
//!
//! `installer/install.sh` translates its options into these flags, so the
//! manifest-writing logic exists exactly once (in the library) and both the
//! app and the installer use it.
//!
//! Nothing here runs during normal native-messaging operation: browsers invoke
//! the host with no arguments (Firefox adds the add-on id and Chrome on
//! Windows adds the origin), and only an explicit `--install`,
//! `--uninstall` or `--help` selects this mode.

use std::path::PathBuf;

use friendlypass_browser::native_messaging::{
    self, Browser, InstallOptions, Platform, DEFAULT_CHROME_EXTENSION_ID,
    DEFAULT_FIREFOX_EXTENSION_ID,
};

const HELP: &str = "\
friendlypass-browser-host --install|--uninstall [options]

Writes or removes the native-messaging manifest
(org.friendlypass.browser.json) for this host. Used by the app's Browser
Integration settings and by installer/install.sh. With no --install,
--uninstall or --help the binary runs as the native-messaging host.

Options:
  --install                       Write the manifests.
  --uninstall                     Remove this host's manifests.
  --browser NAME                  chrome, chromium, brave, edge or firefox.
                                  Repeatable; default: all.
  --home DIR                      Use DIR as $HOME (default: $HOME).
  --platform macos|linux          Override platform detection (tests).
  --host-path PATH                Host binary to register. Default: this
                                  executable.
  --extension-id ID               Chrome-family extension id (32 chars a-p).
                                  Default: the id pinned in the extension
                                  manifest key (pfdmagadklmhbghfipamhfbphcljdkbi).
  --firefox-extension-id ID       Firefox add-on id. Default:
                                  friendlypass@friendlypass.org.
  --dry-run                       Print what would change, write nothing.
  -h, --help                      This help.

The manifests live in each browser's per-user NativeMessagingHosts directory.
Only org.friendlypass.browser.json is ever touched.
";

/// If the arguments request install mode, run it and return the exit code.
/// Returns `None` for a normal native-messaging launch.
pub fn run_if_requested<I>(args: I) -> Option<i32>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    let install_mode = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--install" | "--uninstall" | "-h" | "--help"));
    if !install_mode {
        return None;
    }
    Some(match run(&args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("friendlypass-browser-host: {error:#}");
            2
        }
    })
}

fn run(args: &[String]) -> anyhow::Result<()> {
    let parsed = Parsed::parse(args)?;
    let Some(mode) = parsed.mode else {
        print!("{HELP}");
        return Ok(());
    };

    let platform = parsed.platform.or_else(Platform::current).ok_or_else(|| {
        anyhow::anyhow!("unsupported platform (only macOS and Linux are supported)")
    })?;
    let home = parsed
        .home
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; pass --home DIR"))?;

    let mut options = InstallOptions::new(home, platform, parsed.host_path.unwrap_or_default());
    options.chrome_extension_id = parsed
        .chrome_extension_id
        .unwrap_or_else(|| DEFAULT_CHROME_EXTENSION_ID.to_owned());
    options.firefox_extension_id = parsed
        .firefox_extension_id
        .unwrap_or_else(|| DEFAULT_FIREFOX_EXTENSION_ID.to_owned());
    options.browsers = if parsed.browsers.is_empty() {
        Browser::ALL.to_vec()
    } else {
        parsed.browsers
    };
    options.dry_run = parsed.dry_run;

    if mode == Mode::Install && options.host_path.as_os_str().is_empty() {
        options.host_path = std::env::current_exe()
            .map_err(|error| anyhow::anyhow!("cannot find this executable: {error}"))?;
    }

    match mode {
        Mode::Install => {
            let report = native_messaging::install(&options)?;
            for path in &report.changed {
                if options.dry_run {
                    println!("would write {}", path.display());
                } else {
                    println!("wrote {}", path.display());
                }
            }
            for path in &report.unchanged {
                println!("unchanged {}", path.display());
            }
            if options.dry_run {
                println!("dry run: nothing written");
            } else {
                println!(
                    "friendlypass native host installed for: {} ({})",
                    ids(&options.browsers),
                    platform.id()
                );
            }
        }
        Mode::Uninstall => {
            let report = native_messaging::uninstall(&options)?;
            for path in &report.removed {
                if options.dry_run {
                    println!("would remove {}", path.display());
                } else {
                    println!("removed {}", path.display());
                }
            }
            for path in &report.absent {
                println!("not installed: {}", path.display());
            }
        }
    }
    Ok(())
}

fn ids(browsers: &[Browser]) -> String {
    browsers
        .iter()
        .map(|browser| browser.id())
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Install,
    Uninstall,
}

#[derive(Debug, Default)]
struct Parsed {
    mode: Option<Mode>,
    dry_run: bool,
    home: Option<PathBuf>,
    platform: Option<Platform>,
    host_path: Option<PathBuf>,
    chrome_extension_id: Option<String>,
    firefox_extension_id: Option<String>,
    browsers: Vec<Browser>,
}

impl Parsed {
    fn parse(args: &[String]) -> anyhow::Result<Parsed> {
        let mut parsed = Parsed::default();
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) => (flag, Some(value.to_owned())),
                None => (arg.as_str(), None),
            };
            let mut take_value = |name: &str| -> anyhow::Result<String> {
                if let Some(value) = &inline {
                    return Ok(value.clone());
                }
                index += 1;
                args.get(index)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))
            };
            match flag {
                "--install" => {
                    if parsed.mode == Some(Mode::Uninstall) {
                        anyhow::bail!("--install and --uninstall are mutually exclusive");
                    }
                    parsed.mode = Some(Mode::Install);
                }
                "--uninstall" => {
                    if parsed.mode == Some(Mode::Install) {
                        anyhow::bail!("--install and --uninstall are mutually exclusive");
                    }
                    parsed.mode = Some(Mode::Uninstall);
                }
                "--dry-run" => parsed.dry_run = true,
                "--home" => parsed.home = Some(PathBuf::from(take_value("--home")?)),
                "--platform" => {
                    let value = take_value("--platform")?;
                    parsed.platform = Some(
                        Platform::from_id(&value)
                            .ok_or_else(|| anyhow::anyhow!("unsupported platform: {value}"))?,
                    );
                }
                "--host-path" => parsed.host_path = Some(PathBuf::from(take_value("--host-path")?)),
                "--extension-id" => {
                    parsed.chrome_extension_id = Some(take_value("--extension-id")?)
                }
                "--firefox-extension-id" => {
                    parsed.firefox_extension_id = Some(take_value("--firefox-extension-id")?)
                }
                "--browser" | "--browsers" => {
                    let value = take_value(flag)?;
                    let mut added = 0;
                    for id in value.split(',') {
                        let id = id.trim();
                        if id.is_empty() {
                            continue;
                        }
                        let browser = Browser::from_id(id).ok_or_else(|| {
                            anyhow::anyhow!(
                                "unknown browser: {id} (known: chrome, chromium, brave, edge, firefox)"
                            )
                        })?;
                        parsed.browsers.push(browser);
                        added += 1;
                    }
                    if added == 0 {
                        anyhow::bail!(
                            "{flag} needs a browser name (chrome, chromium, brave, edge, firefox)"
                        );
                    }
                }
                "-h" | "--help" => {}
                other => anyhow::bail!("unknown argument: {other} (try --help)"),
            }
            index += 1;
        }
        parsed.browsers.sort_by_key(|browser| {
            Browser::ALL
                .iter()
                .position(|candidate| candidate == browser)
                .unwrap_or(usize::MAX)
        });
        parsed.browsers.dedup();
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> anyhow::Result<Parsed> {
        Parsed::parse(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn normal_host_launches_are_not_install_mode() {
        assert!(run_if_requested(Vec::<String>::new()).is_none());
        assert!(run_if_requested(vec!["chrome-extension://abc/".to_owned()]).is_none());
        assert!(run_if_requested(vec!["friendlypass@friendlypass.org".to_owned()]).is_none());
    }

    #[test]
    fn install_flags_are_parsed() {
        let parsed = parse(&[
            "--install",
            "--browser",
            "firefox",
            "--browser=chrome",
            "--home",
            "/tmp/home",
            "--platform=linux",
            "--host-path",
            "/tmp/host",
            "--extension-id=abcdefghijklmnopabcdefghijklmnop",
            "--dry-run",
        ])
        .unwrap();
        assert_eq!(parsed.mode, Some(Mode::Install));
        assert_eq!(parsed.browsers, vec![Browser::Chrome, Browser::Firefox]);
        assert_eq!(parsed.home, Some(PathBuf::from("/tmp/home")));
        assert_eq!(parsed.platform, Some(Platform::Linux));
        assert_eq!(parsed.host_path, Some(PathBuf::from("/tmp/host")));
        assert!(parsed.dry_run);
    }

    #[test]
    fn comma_lists_and_duplicates_are_normalised() {
        let parsed = parse(&["--uninstall", "--browsers", "firefox,chrome,firefox"]).unwrap();
        assert_eq!(parsed.mode, Some(Mode::Uninstall));
        assert_eq!(parsed.browsers, vec![Browser::Chrome, Browser::Firefox]);
    }

    #[test]
    fn bad_arguments_are_rejected() {
        assert!(parse(&["--install", "--browser", "netscape"]).is_err());
        assert!(parse(&["--install", "--platform", "windows"]).is_err());
        assert!(parse(&["--install", "--extension-id"]).is_err());
        assert!(parse(&["--install", "--uninstall"]).is_err());
        assert!(parse(&["--install", "--nonsense"]).is_err());
        assert!(parse(&["--install", "--browser", ""]).is_err());
    }
}
