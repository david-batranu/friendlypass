//! Build script: embed the KeePass standard icons (rasterized from the
//! original KeePassXC SVGs in `icons/`) as a compile-time table.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("icons");
    println!("cargo:rerun-if-changed={}", dir.display());

    let mut entries: Vec<(usize, String)> = fs::read_dir(&dir)
        .expect("icons directory")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            if p.extension()?.to_str()? != "png" {
                return None;
            }
            let stem = p.file_stem()?.to_str()?;
            let n: usize = stem.parse().ok()?;
            Some((n, p.display().to_string()))
        })
        .collect();
    entries.sort();

    let out = env::var("OUT_DIR").unwrap();
    let mut code = String::from("/// Number of KeePass standard icons (0..=68).\n");
    code.push_str(&format!(
        "pub const STANDARD_ICON_COUNT: usize = {};\n",
        entries.len()
    ));
    code.push_str("pub const STANDARD_ICONS: &[(usize, &[u8])] = &[\n");
    for (n, path) in &entries {
        code.push_str(&format!("    ({n}, include_bytes!(r\"{path}\")),\n"));
    }
    code.push_str("];\n");
    fs::write(Path::new(&out).join("icons.rs"), code).unwrap();
}
