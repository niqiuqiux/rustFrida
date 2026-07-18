use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
    let profile_dir = current_profile_dir();
    let profile_name = profile_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("Cargo profile directory must have a valid UTF-8 name");
    let target_dir = profile_dir
        .parent()
        .expect("Cargo profile directory must be below a target directory");
    let agent_profile = std::env::var("RUSTFRIDA_AGENT_PROFILE").unwrap_or_else(|_| profile_name.to_owned());
    let agent_path = target_dir.join(&agent_profile).join("libagent.so");
    let map_path = profile_dir.join("rustfrida.map");

    // 当 agent.so 或 helper shellcode 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo:rerun-if-env-changed=RUSTFRIDA_AGENT_PROFILE");
    println!("cargo:rerun-if-changed={}", agent_path.display());
    println!("cargo:rustc-env=RUSTFRIDA_AGENT_SO_PATH={}", agent_path.display());
    println!("cargo:rustc-link-arg=-Wl,-Map={}", map_path.display());
    println!("cargo:rerun-if-changed=../loader/build/bootstrapper.bin");
    println!("cargo:rerun-if-changed=../loader/build/rustfrida-loader.bin");

    let helper_inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    for input in helper_inputs {
        println!("cargo:rerun-if-changed=../{}", input);
    }

    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "aarch64-linux-android" && helpers_are_stale(workspace_root) {
        // Windows 通常只有 `python`（无 `python3`），类 Unix 用 `python3`。
        // 按平台优先级尝试可用的解释器。
        let candidates: &[&str] = if cfg!(target_os = "windows") {
            &["python", "python3"]
        } else {
            &["python3", "python"]
        };
        let script = workspace_root.join("loader/build_helpers.py");
        let mut ran = false;
        let mut last_err = None;
        for py in candidates {
            match std::process::Command::new(py)
                .arg(&script)
                .current_dir(workspace_root)
                .status()
            {
                Ok(status) => {
                    if !status.success() {
                        panic!("loader/build_helpers.py failed with status {}", status);
                    }
                    ran = true;
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if !ran {
            panic!(
                "failed to run loader/build_helpers.py (tried {:?}): {:?}",
                candidates, last_err
            );
        }
    }

    if std::env::var_os("CARGO_FEATURE_QBDI").is_some() {
        let helper_profile = std::env::var("RUSTFRIDA_QBDI_PROFILE").unwrap_or_else(|_| agent_profile.clone());
        let helper_path = target_dir.join(helper_profile).join("libqbdi_helper.so");
        println!("cargo:rerun-if-env-changed=RUSTFRIDA_QBDI_PROFILE");
        println!("cargo:rustc-env=QBDI_HELPER_SO_PATH={}", helper_path.display());
        println!("cargo:rerun-if-changed={}", helper_path.display());
    }
}

fn current_profile_dir() -> PathBuf {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    out_dir
        .ancestors()
        .nth(3)
        .expect("unexpected Cargo OUT_DIR layout")
        .to_path_buf()
}

fn helpers_are_stale(workspace_root: &Path) -> bool {
    let inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    let outputs = ["loader/build/bootstrapper.bin", "loader/build/rustfrida-loader.bin"];

    let newest_input = inputs
        .iter()
        .filter_map(|path| modified_time(&workspace_root.join(path)))
        .max();
    let oldest_output = outputs
        .iter()
        .map(|path| modified_time(&workspace_root.join(path)))
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().min());

    match (newest_input, oldest_output) {
        (_, None) => true,
        (Some(input), Some(output)) => input > output,
        (None, Some(_)) => false,
    }
}

fn modified_time(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|metadata| metadata.modified()).ok()
}
