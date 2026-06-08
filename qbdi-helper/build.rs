fn main() {
    println!("cargo:rerun-if-env-changed=NDK_PATH");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
    println!("cargo:rerun-if-env-changed=ANDROID_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_SDK_ROOT");

    cc::Build::new()
        .file("../agent/src/hide_soinfo.c")
        .compile("hide_soinfo");

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("qbdi-helper must live under the workspace root");
    let qbdi_archive = workspace_root.join("qbdi/libQBDI.a");
    validate_qbdi_archive(&qbdi_archive);

    println!("cargo:rustc-cdylib-link-arg={}", qbdi_archive.display());
    println!("cargo:rustc-link-lib=log");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "android" && target_arch == "aarch64" {
        let ndk_path = find_ndk_path();
        let cxx_lib_dir = std::path::PathBuf::from(&ndk_path)
            .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android");
        let cxx_static = cxx_lib_dir.join("libc++_static.a");
        let cxxabi = cxx_lib_dir.join("libc++abi.a");

        println!("cargo:rustc-cdylib-link-arg={}", cxx_static.display());
        println!("cargo:rustc-cdylib-link-arg={}", cxxabi.display());
        println!("cargo:rustc-link-lib=dylib=c");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }

    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,rust_get_hide_result,--export-dynamic-symbol=get_hide_result,--export-dynamic-symbol=rust_get_hide_result"
    );
    if std::env::var_os("CARGO_FEATURE_PTHREAD_SHIM").is_some() {
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_create,-u,pthread_detach,-u,nanosleep,--export-dynamic-symbol=pthread_create,--export-dynamic-symbol=pthread_detach,--export-dynamic-symbol=nanosleep"
        );
    }
    println!("cargo:rerun-if-changed=../agent/src/hide_soinfo.c");
    println!("cargo:rerun-if-changed={}", qbdi_archive.display());
}

fn find_ndk_path() -> String {
    for key in ["NDK_PATH", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return value;
            }
        }
    }

    let sdk_root = std::env::var("ANDROID_HOME")
        .or_else(|_| std::env::var("ANDROID_SDK_ROOT"))
        .ok()
        .or_else(|| std::env::var("HOME").ok().map(|home| format!("{home}/Android/Sdk")));

    if let Some(sdk_root) = sdk_root {
        let ndk_dir = std::path::Path::new(&sdk_root).join("ndk");
        if let Ok(entries) = std::fs::read_dir(&ndk_dir) {
            let mut versions = entries
                .flatten()
                .filter_map(|entry| {
                    let path = entry.path();
                    if path.is_dir() {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            versions.sort();
            if let Some(path) = versions.pop() {
                return path.display().to_string();
            }
        }
    }

    panic!("NDK path not found; set NDK_PATH or ANDROID_NDK_HOME");
}

fn validate_qbdi_archive(path: &std::path::Path) {
    let data = std::fs::read(path).unwrap_or_else(|err| {
        panic!("QBDI archive not found at {}: {err}", path.display());
    });

    if data.starts_with(b"version https://git-lfs.github.com/spec/v1") {
        panic!(
            "QBDI archive at {} is a Git LFS pointer, not libQBDI.a. Install git-lfs or replace it with the real archive before building qbdi-helper.",
            path.display()
        );
    }

    if !(data.starts_with(b"!<arch>\n") || data.starts_with(b"!<thin>\n")) {
        panic!(
            "QBDI archive at {} is not a valid ar archive; got {} bytes with unexpected header.",
            path.display(),
            data.len()
        );
    }
}
