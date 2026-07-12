use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_HASH_DOMAIN: &[u8] = b"nerb-native-build-source-v1\0";
const EXPECTED_SOURCE_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "src/bank.rs",
    "src/engine.rs",
    "src/error.rs",
    "src/flags.rs",
    "src/formats.rs",
    "src/ids.rs",
    "src/lib.rs",
    "src/match_buffer.rs",
];

fn rust_sources(root: &Path, directory: &Path, output: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("native source directory must be readable") {
        let entry = entry.expect("native source inventory entry must be readable");
        let path = entry.path();
        let file_type = entry
            .file_type()
            .expect("native source inventory metadata must be readable");
        if file_type.is_dir() {
            rust_sources(root, &path, output);
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            output.push(
                path.strip_prefix(root)
                    .expect("native source must remain below the crate root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn normalized_lf(path: &Path) -> Vec<u8> {
    let source =
        fs::read(path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    let mut normalized = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if source[index] == b'\r' {
            assert!(
                source.get(index + 1) == Some(&b'\n'),
                "native source {} contains a bare carriage return",
                path.display()
            );
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(source[index]);
            index += 1;
        }
    }
    normalized
}

fn main() {
    let root = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("crate root must be available"),
    );
    let mut inventory = vec![
        "Cargo.lock".to_string(),
        "Cargo.toml".to_string(),
        "build.rs".to_string(),
    ];
    rust_sources(&root, &root.join("src"), &mut inventory);
    inventory.sort();
    let expected = EXPECTED_SOURCE_FILES
        .iter()
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        inventory, expected,
        "native build-source inventory changed; update EXPECTED_SOURCE_FILES deliberately"
    );

    let mut digest = Sha256::new();
    digest.update(SOURCE_HASH_DOMAIN);
    for relative in EXPECTED_SOURCE_FILES {
        let payload = normalized_lf(&root.join(relative));
        let path_bytes = relative.as_bytes();
        digest.update((path_bytes.len() as u64).to_be_bytes());
        digest.update(path_bytes);
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);
        println!("cargo:rerun-if-changed={relative}");
    }
    println!("cargo:rerun-if-changed=src");
    println!(
        "cargo:rustc-env=NERB_NATIVE_BUILD_SOURCE_SHA256=sha256:{:x}",
        digest.finalize()
    );
}
