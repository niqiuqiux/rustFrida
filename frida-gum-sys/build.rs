/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

extern crate bindgen;

use ring::digest::{Context, SHA256};
use serde::Deserialize;
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const LOCAL_DEVKIT_ENV: &str = "FRIDA_GUM_DEVKIT_DIR";
const INTERCEPTOR_DISCARD_FIX: &str = "8f51400554b0d16a4a383a901b01040687fd7f80";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevkitManifest {
    schema_version: u32,
    kind: String,
    frida_revision: String,
    gum_revision: String,
    required_fixes: Vec<String>,
    target: DevkitTarget,
    artifacts: DevkitArtifacts,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DevkitTarget {
    os: String,
    arch: String,
}

#[derive(Deserialize)]
struct DevkitArtifacts {
    header: DevkitArtifact,
    archive: DevkitArtifact,
}

#[derive(Deserialize)]
struct DevkitArtifact {
    path: String,
    size: u64,
    sha256: String,
}

fn sha256(path: &Path) -> String {
    let mut file =
        File::open(path).unwrap_or_else(|error| panic!("failed to open devkit artifact {}: {error}", path.display()));
    let mut digest = Context::new(&SHA256);
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("failed to read devkit artifact {}: {error}", path.display()));
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut result = String::with_capacity(64);
    for byte in digest.finish().as_ref() {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn validate_artifact(devkit_dir: &Path, artifact: &DevkitArtifact) {
    let path = devkit_dir.join(&artifact.path);
    let metadata = path
        .metadata()
        .unwrap_or_else(|error| panic!("missing devkit artifact {}: {error}", path.display()));
    assert!(metadata.is_file(), "devkit artifact is not a file: {}", path.display());
    assert_eq!(
        metadata.len(),
        artifact.size,
        "devkit artifact size mismatch: {}",
        path.display()
    );
    assert_eq!(
        sha256(&path),
        artifact.sha256,
        "devkit artifact SHA-256 mismatch: {}",
        path.display()
    );
}

fn use_local_devkit(devkit_dir: PathBuf, target_os: &str, target_arch: &str, use_gum_js: bool) -> (PathBuf, bool) {
    assert!(!use_gum_js, "{LOCAL_DEVKIT_ENV} currently provides a Gum-only devkit");

    let manifest: DevkitManifest =
        serde_json::from_str(include_str!("FRIDA_GUM_DEVKIT.json")).expect("invalid FRIDA_GUM_DEVKIT.json");
    assert_eq!(manifest.schema_version, 1, "unsupported Gum devkit manifest schema");
    assert_eq!(manifest.kind, "gum", "local devkit manifest kind mismatch");
    assert_eq!(manifest.target.os, target_os, "local devkit target OS mismatch");
    assert_eq!(
        manifest.target.arch, target_arch,
        "local devkit target architecture mismatch"
    );
    assert_eq!(
        manifest.frida_revision.len(),
        40,
        "invalid Frida source revision in local devkit manifest"
    );
    assert_eq!(
        manifest.gum_revision.len(),
        40,
        "invalid Gum source revision in local devkit manifest"
    );
    assert!(
        !manifest.required_fixes.is_empty(),
        "local devkit manifest does not record required fixes"
    );

    validate_artifact(&devkit_dir, &manifest.artifacts.header);
    validate_artifact(&devkit_dir, &manifest.artifacts.archive);

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    let pinned_archive = out_dir.join("libfrida-gum-pinned.a");
    fs::copy(devkit_dir.join(&manifest.artifacts.archive.path), &pinned_archive).unwrap_or_else(|error| {
        panic!(
            "failed to stage pinned Gum archive {}: {error}",
            pinned_archive.display()
        )
    });
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!(
        "cargo:warning=Using pinned local Gum devkit at {} (Gum revision {})",
        devkit_dir.display(),
        manifest.gum_revision
    );

    let has_interceptor_discard_fix = manifest.required_fixes.iter().any(|fix| fix == INTERCEPTOR_DISCARD_FIX);

    (devkit_dir, has_interceptor_discard_fix)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=FRIDA_GUM_DEVKIT.json");
    println!("cargo:rerun-if-env-changed={LOCAL_DEVKIT_ENV}");
    println!("cargo:rustc-check-cfg=cfg(frida_gum_modern_interceptor)");
    println!("cargo:rustc-check-cfg=cfg(frida_gum_interceptor_discard)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();

    let docs = std::env::var("DOCS_RS").is_ok();
    // We always use frida-gumjs.h for docs to not have to ship two big header files in this repo.
    let use_gum_js = cfg!(feature = "js") || (!cfg!(feature = "auto-download") && docs);
    #[cfg(any(
        feature = "event-sink",
        feature = "invocation-listener",
        feature = "stalker-observer",
        feature = "stalker-params"
    ))]
    let use_gum_js_env = if use_gum_js { "1" } else { "0" };

    #[cfg(feature = "event-sink")]
    {
        println!("cargo:rerun-if-changed=event_sink.c");
        println!("cargo:rerun-if-changed=event_sink.h");
    }

    #[cfg(feature = "invocation-listener")]
    {
        println!("cargo:rerun-if-changed=invocation_listener.c");
        println!("cargo:rerun-if-changed=invocation_listener.h");
        println!("cargo:rerun-if-changed=interceptor_discard.c");
        println!("cargo:rerun-if-changed=probe_listener.c");
        println!("cargo:rerun-if-changed=probe_listener.h");
    }

    #[cfg(feature = "stalker-observer")]
    {
        println!("cargo:rerun-if-changed=stalker_observer.c");
        println!("cargo:rerun-if-changed=stalker_observer.h");
    }

    #[cfg(feature = "stalker-params")]
    {
        println!("cargo:rerun-if-changed=stalker_params.c");
        println!("cargo:rerun-if-changed=stalker_params.h");
    }

    println!("cargo:rustc-link-search={}", env::var("CARGO_MANIFEST_DIR").unwrap());

    let (include_dir, has_interceptor_discard_fix) = if let Some(devkit_dir) = env::var_os(LOCAL_DEVKIT_ENV) {
        let (include_dir, has_interceptor_discard_fix) =
            use_local_devkit(PathBuf::from(devkit_dir), &target_os, &target_arch, use_gum_js);
        (Some(include_dir), has_interceptor_discard_fix)
    } else {
        #[cfg(feature = "auto-download")]
        {
            use frida_build::download_and_use_devkit;
            let kind = if cfg!(feature = "js") { "gumjs" } else { "gum" };
            (
                Some(PathBuf::from(download_and_use_devkit(
                    kind,
                    include_str!("FRIDA_VERSION").trim(),
                ))),
                false,
            )
        }
        #[cfg(not(feature = "auto-download"))]
        {
            (None, false)
        }
    };
    if include_dir.is_some() {
        println!("cargo:rustc-cfg=frida_gum_modern_interceptor");
    }
    if has_interceptor_discard_fix {
        println!("cargo:rustc-cfg=frida_gum_interceptor_discard");
    }

    #[cfg(not(feature = "auto-download"))]
    if include_dir.is_none() {
        if cfg!(feature = "js") {
            println!("cargo:rustc-link-lib=frida-gumjs");
        } else {
            println!("cargo:rustc-link-lib=frida-gum");
        }
    }

    if target_os != "android" && (target_os == "linux" || target_vendor == "apple") {
        println!("cargo:rustc-link-lib=pthread");
    }

    let bindings = bindgen::Builder::default()
        .use_core()
        .formatter(bindgen::Formatter::Prettyplease);

    let bindings = if let Some(ref include_dir) = include_dir {
        bindings.clang_arg(format!("-I{}", include_dir.display()))
    } else if docs {
        bindings.clang_arg("-Iinclude")
    } else {
        bindings.clang_arg("-I.")
    };

    let bindings = if use_gum_js {
        bindings
            .clang_arg("-DUSE_GUM_JS=1")
            .header_contents("gum.h", "#include <frida-gumjs.h>")
    } else {
        bindings
            .clang_arg("-DUSE_GUM_JS=0")
            .header_contents("gum.h", "#include <frida-gum.h>")
    };

    let bindings = bindings
        .header("event_sink.h")
        .header("invocation_listener.h")
        .header("probe_listener.h")
        .header("stalker_observer.h")
        .header("stalker_params.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .blocklist_type("GumChainedPtr64Rebase")
        .blocklist_type("GumChainedPtrArm64eRebase")
        .blocklist_type("_GumChainedPtr64Rebase")
        .blocklist_type("_GumChainedPtrArm64eRebase")
        .generate_comments(false)
        .layout_tests(false)
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();

    #[cfg(feature = "event-sink")]
    {
        let mut builder = cc::Build::new();

        if let Some(ref include_dir) = include_dir {
            builder.include(include_dir);
        } else if docs {
            builder.include("include");
        } else {
            builder.include(".");
        }
        builder
            .file("event_sink.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("event_sink");
    }

    #[cfg(feature = "invocation-listener")]
    {
        let mut builder = cc::Build::new();

        if let Some(ref include_dir) = include_dir {
            builder.include(include_dir);
        } else if docs {
            builder.include("include");
        } else {
            builder.include(".");
        }
        builder
            .file("invocation_listener.c")
            .file("interceptor_discard.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("invocation_listener");

        let mut builder = cc::Build::new();

        if let Some(ref include_dir) = include_dir {
            builder.include(include_dir);
        } else if docs {
            builder.include("include");
        } else {
            builder.include(".");
        }
        builder
            .file("probe_listener.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("probe_listener");
    }

    #[cfg(feature = "stalker-observer")]
    {
        let mut builder = cc::Build::new();

        if let Some(ref include_dir) = include_dir {
            builder.include(include_dir);
        } else if docs {
            builder.include("include");
        } else {
            builder.include(".");
        }

        builder
            .file("stalker_observer.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("stalker_observer");
    }

    #[cfg(feature = "stalker-params")]
    {
        let mut builder = cc::Build::new();

        if let Some(ref include_dir) = include_dir {
            builder.include(include_dir);
        } else if docs {
            builder.include("include");
        } else {
            builder.include(".");
        }

        builder
            .file("stalker_params.c")
            .opt_level(3)
            .define("USE_GUM_JS", use_gum_js_env)
            .compile("stalker_params");
    }

    // Keep the Gum archive after the C compatibility libraries. The fixed
    // devkit also has a direct Rust FFI reference to its private discard helper.
    if env::var_os(LOCAL_DEVKIT_ENV).is_some() {
        println!("cargo:rustc-link-lib=static=frida-gum-pinned");
    }

    if target_os == "windows" {
        for lib in [
            "dnsapi", "iphlpapi", "psapi", "winmm", "ws2_32", "advapi32", "crypt32", "gdi32", "kernel32", "ole32",
            "secur32", "shell32", "shlwapi", "user32", "setupapi",
        ] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }

    /* GUMJS contains v8 for some architectures, thus it needs to link stdc++ */
    #[cfg(all(feature = "js", target_os = "linux"))]
    println!("cargo:rustc-link-lib=dylib=stdc++");

    #[cfg(all(feature = "js", target_os = "android"))]
    println!("cargo:rustc-link-lib=c++");

    #[cfg(all(feature = "js", target_os = "macos"))]
    println!("cargo:rustc-link-lib=resolv");
}
