fn main() -> anyhow::Result<()> {
    let profile_dir = current_profile_dir()?;
    let map_path = profile_dir.join("libagent.map");

    // 编译 C 代码

    // Do not link hide_soinfo.c in the custom-linker injection path.
    // That code is only valid for Android linker/dlopen-managed modules; our
    // loader maps the agent itself, so no linker soinfo exists to hide.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_create,--export-dynamic-symbol=pthread_create");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_detach,--export-dynamic-symbol=pthread_detach");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,nanosleep,--export-dynamic-symbol=nanosleep");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--wrap=dlsym");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--wrap=pthread_mutex_lock");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--wrap=pthread_mutex_unlock");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--wrap=pthread_mutex_destroy");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-Map={}", map_path.display());

    Ok(())
}

fn current_profile_dir() -> anyhow::Result<std::path::PathBuf> {
    let out_dir =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| anyhow::anyhow!("OUT_DIR not set"))?);
    out_dir
        .ancestors()
        .nth(3)
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("unexpected Cargo OUT_DIR layout: {}", out_dir.display()))
}
