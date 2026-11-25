# NOTICE

friendlypass is free software under the **GNU General Public License, version 3
only** (GPL-3.0-only). The full licence text is in [`LICENSE`](LICENSE).

This file records what friendlypass is derived from, the third-party assets it
contains, and the warranty disclaimer. It is not itself a licence; the
licences named below govern the material they are attached to.

## What friendlypass is derived from

### KeePassXC

friendlypass is a Rust reimplementation of KeePassXC's headless core and GUI
workflow. The upstream C++ source is KeePassXC 2.8.0
(<https://github.com/keepassxreboot/keepassxc>, checkout `cd42236`), licensed
**GPL-2 or GPL-3** (not "or later"; see `keepassxc/COPYING` in the upstream
tree). Because friendlypass also contains GPL-3-only material, the combined
work is distributed under GPL-3.0-only.

KeePassXC copyright, as listed in the header of its `COPYING` file:

```
KeePassXC - http://www.keepassxc.org/
Copyright (C) 2016-2023 KeePassXC Team <team@keepassxc.org>

2010-2012, Felix Geyer <debfx@fobos.de>
2011-2012, Florian Geyer <blueice@fobos.de>
2012, Tobias Tangemann
2007, Trolltech ASA <info@trolltech.com>
2012, Intel Corporation
2012, Nokia Corporation and/or its subsidiary(-ies)
2000-2008, Tom Sato <VEF00200@nifty.ne.jp>
2013, Laszlo Papp <lpapp@kde.org>
2013, David Faure <faure@kde.org>
2016-2023, KeePassXC Team <team@keepassxc.org>
```

The "KeePassXC Team" copyright holder is formed by droidmonkey, phoerious,
varjolintu, hifi and louib; every other contributor is listed at
<https://github.com/keepassxreboot/keepassxc/graphs/contributors>.

The Rust code in `crates/` is a behavioural port, not a line-by-line
translation of the C++ sources; it is nonetheless a derived work of KeePassXC
and is distributed under the GPL.

### keepassxc-browser

`extension/` is a hard fork of
[keepassxc-browser](https://github.com/keepassxreboot/keepassxc-browser),
snapshot commit `9d27471ab0b8f913f1b7d6b36b74cbcba0170613` (v1.10.4.1,
2026-11-19), licensed **GPL-3.0** only. Copyright KeePassXC Team and the
keepassxc-browser contributors.

The background/session layer was rewritten against the documented wire
protocol, but the content-script layer is a port of upstream
`keepassxc-browser/content/*.js`: `src/content/ui.ts` (from `ui.js`),
`fields.ts` (`fields.js`, including `getNewPassword` ported verbatim),
`fill.ts` (`fill.js`), `observer.ts` (`observer.js`), `totp-field.ts`
(`totp-field.js`) and `username-field.ts` (`username-field.js`). Those files
remain under GPL-3.0; the repository as a whole is distributed under
GPL-3.0-only.

### Changes from upstream (GPL-3.0 § 5(a))

friendlypass is a modified version of the two projects above, not a verbatim
copy. The modifications are: the C++ KeePassXC core and GUI were reimplemented
in Rust; the browser extension was rebranded and its background/session layer
rewritten, while its content scripts were ported to TypeScript; the KeePassXC
database icons were rasterized to 32×32 PNGs; and the application artwork was
replaced with friendlypass branding. The upstream snapshots used are
KeePassXC 2.8.0 (checkout `cd42236`, 2026-11-17) and keepassxc-browser
v1.10.4.1 (`9d27471`, 2026-11-19). This notice is dated 2026-11-25; the
detailed modification history is recorded in this repository's commits.

## Third-party assets in this repository

| Location | Upstream source | Licence | Copyright / evidence |
|---|---|---|---|
| `crates/friendlypass-gui/icons/0.png` … `68.png` (69 PNGs, 32×32) | `keepassxc/share/icons/database/C00_Password.svg` … `C68_BlackBerry.svg` | mixed, see the icon table below | Rasterized from the KeePassXC database icon set (`crates/friendlypass-gui/build.rs` says so). 62 of the 69 PNGs are pixel-identical to a fresh `rsvg-convert -w 32 -h 32` render of the matching upstream SVG; the remaining 7 (13, 17, 18, 19, 26, 63, 65) appear to be the same upstream icons rasterized with a different crop/scale. |
| `fixtures/Compressed.kdbx`, `Format400.kdbx`, `NonAscii.kdbx`, `ProtectedStrings.kdbx` | `keepassxc/tests/data/` (same names) | GPL-2 or GPL-3 | Byte-identical (`cmp`, identical MD5) to the upstream test databases. |
| `fixtures/keepass1.kdb` | `keepassxc/tests/data/basic.kdb` | GPL-2 or GPL-3 | Byte-identical (MD5 `72abd1f353ca233f2f02278d36a05a17`); renamed for its KDB/AES content. |
| `fixtures/keepass1-twofish.kdb` | `keepassxc/tests/data/Twofish.kdb` | GPL-2 or GPL-3 | Byte-identical (MD5 `c11b93fe3510dea2d6c3193531c974d2`); renamed for its KDB/Twofish content. |
| `extension/src/content/*.ts` (see above) | `keepassxc-browser/content/*.js` | GPL-3.0 | Copyright KeePassXC Team; ported functions and constants, marked "ported from upstream" in each file header. |
| `vendor/challenge-response/` | `challenge-response` crate (vendored patch; see `Cargo.toml`) | MIT OR Apache-2.0 | Copyright (c) 2016 Flavio Oliveira, (c) 2018 Pierre-Étienne Meunier, (c) 2024 Ashutosh Varma, (c) 2024 louib. The vendored `LICENSE` file carries the dual-licence statement; friendlypass relies on the MIT option. |
| `fixtures/sample4.kdbx`, `sample4_argon2.kdbx`, `sample4_keyfile.kdbx`, `sample4.keyx` | none — generated for this project with `keepassxc-cli` 2.8.0 | GPL-3.0-only (project test data) | Documented in `README.md` ("Fixture passwords"); not copied from upstream. |
| `extension/src/icons/*.png`, `crates/friendlypass-gui/assets/app-icon.png`, `packaging/linux/icons/**`, `packaging/macos/AppIcon.icns`, `branding/**` | none — friendlypass artwork | GPL-3.0-only (project artwork) | All derived from `branding/friendlypass-logo.jpg` by `branding/generate-icons.sh`. |
| `docs/screenshots/*.png`, `protocol/fixtures/*.json` | none — generated | GPL-3.0-only | Screenshots of friendlypass; protocol vectors generated by `protocol/gen-fixtures.mjs`. |

No fonts, wordlists, KeePassXC translation catalogues or zxcvbn data files
were copied into this repository. zxcvbn is used as an unmodified Rust crate
dependency (`zxcvbn 3`), whose own licence applies. Other Rust and npm
dependencies are listed in `Cargo.lock` and `extension/package-lock.json` and
carry their own licences; only the dual-licensed `challenge-response` crate is
vendored in-tree.

### Licence of the copied database icons

The KeePassXC `COPYING` file assigns the database icon set to four groups. The
local PNG numbers map directly to the upstream `C0N` file names:

| Local icons | Upstream files | Licence | Copyright |
|---|---|---|---|
| 0–6, 8–16, 19–25, 28–34, 36, 39–43, 47–50, 55–58, 59, 60, 62, 63, 65, 67, 68 | `C00`–`C06`, `C08`–`C16`, `C19`–`C25`, `C28`–`C34`, `C36`, `C39`–`C43`, `C47`–`C50`, `C55`–`C58_KGPG`, `C59`, `C60`, `C62`, `C63`, `C65`, `C67`, `C68` | MIT | No copyright line recorded upstream; taken from <https://github.com/icons8/flat-color-icons> |
| 7, 17, 18, 26, 27, 35, 38, 44, 51, 52, 54, 66 | `C07`, `C17`, `C18`, `C26`, `C27`, `C35`, `C38`, `C44`, `C51`, `C52`, `C54`, `C66` | CC0-1.0 | No copyright line recorded upstream; taken from <https://github.com/paomedia/small-n-flat> |
| 37, 45, 46, 53, 61 | `C37_KPercentage`, `C45_Cancel`, `C46_Help`, `C53_Apply`, `C61_Services` | MIT | Copyright 2022 KeePassXC Team <team@keepassxc.org> |
| 64 | `C64_Apple` | GPL-2.0-or-later | `Copyright: GPL-2+` as recorded upstream (the copyright field in KeePassXC's `COPYING`); taken from the Simple Icons repo (<https://github.com/simple-icons/simple-icons/>) |

`C58_KPGP.svg` is a duplicate of `C58_KGPG.svg`; both are rendered by the
local icon 58 and are covered by the MIT row above.

## Licence texts

The texts that must accompany the copied assets are in `LICENSES/`:

| File | Applies to |
|---|---|
| [`LICENSE`](LICENSE) (GPL-3.0-only) | friendlypass as a whole |
| [`LICENSES/MIT.txt`](LICENSES/MIT.txt) | icons 0–6, 8–16, 19–25, 28–34, 36, 37, 39–43, 45–50, 53, 55–60, 61–63, 65, 67, 68; vendored `challenge-response` (MIT option) |
| [`LICENSES/CC0-1.0.txt`](LICENSES/CC0-1.0.txt) | icons 7, 17, 18, 26, 27, 35, 38, 44, 51, 52, 54, 66 |
| [`LICENSES/GPL-2.0-or-later.txt`](LICENSES/GPL-2.0-or-later.txt) | icon 64 (`C64_Apple`, GPL-2+) and the KeePassXC test databases, which are GPL-2 or GPL-3 |
| GPL-3.0 → `LICENSE` | keepassxc-browser content-script ports and all KeePassXC-derived code |

For the KeePassXC project as a whole the upstream `COPYING` records
GPL-2 or GPL-3; the GPL-3 text is reproduced in `LICENSE` and the GPL-2 text
in `LICENSES/GPL-2.0-or-later.txt`.

## Warranty disclaimer

friendlypass is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3 only.

friendlypass is distributed in the hope that it will be useful, but **WITHOUT
ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License in
`LICENSE` for more details. **There is ABSOLUTELY NO WARRANTY.**

friendlypass is an independent project. It is not affiliated with, endorsed
by, or supported by the KeePassXC Team or the keepassxc-browser maintainers.
