//! Gum-backed services for the Frida-compatible Module object model.

#![cfg(feature = "frida-gum")]

use frida_gum_sys as gum_sys;
use quickjs_hook::{ModuleBackend, ModuleDependencyDetails, ModuleDetails, ModuleIdentity, ModuleSectionDetails};
use std::ffi::{CStr, CString};

fn c_string(value: &str, label: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{label} contains a NUL byte"))
}

unsafe fn optional_string(value: *const gum_sys::gchar) -> Option<String> {
    (!value.is_null()).then(|| CStr::from_ptr(value).to_string_lossy().into_owned())
}

unsafe fn module_details(module: *mut gum_sys::GumModule) -> Option<ModuleDetails> {
    if module.is_null() {
        return None;
    }
    let name = optional_string(gum_sys::gum_module_get_name(module))?;
    let path = optional_string(gum_sys::gum_module_get_path(module))?;
    let range = gum_sys::gum_module_get_range(module);
    if range.is_null() {
        return None;
    }
    Some(ModuleDetails {
        name,
        version: optional_string(gum_sys::gum_module_get_version(module)),
        path,
        base: (*range).base_address,
        size: (*range).size as u64,
    })
}

unsafe extern "C" fn collect_module(
    module: *mut gum_sys::GumModule,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if let Some(details) = module_details(module) {
        (&mut *(user_data as *mut Vec<ModuleDetails>)).push(details);
    }
    1
}

fn enumerate_modules() -> Vec<ModuleDetails> {
    let mut modules: Vec<ModuleDetails> = Vec::new();
    unsafe {
        gum_sys::gum_process_enumerate_modules(Some(collect_module), &mut modules as *mut Vec<ModuleDetails> as *mut _);
    }
    modules.sort_by_key(|module| module.base);
    modules
}

struct OwnedModule(*mut gum_sys::GumModule);

impl Drop for OwnedModule {
    fn drop(&mut self) {
        unsafe {
            gum_sys::g_object_unref(self.0.cast());
        }
    }
}

fn find_module(identity: &ModuleIdentity) -> Result<OwnedModule, String> {
    let path = c_string(&identity.path, "module path")?;
    let name = c_string(&identity.name, "module name")?;
    let mut module = unsafe { gum_sys::gum_process_find_module_by_name(path.as_ptr()) };
    if module.is_null() {
        module = unsafe { gum_sys::gum_process_find_module_by_name(name.as_ptr()) };
    }
    if module.is_null() {
        module = unsafe { gum_sys::gum_process_find_module_by_address(identity.base) };
    }
    if module.is_null() {
        return Err("module is no longer present in Gum's registry".to_string());
    }

    let owned = OwnedModule(module);
    let actual = unsafe { module_details(owned.0) }.ok_or_else(|| "unable to inspect Gum module".to_string())?;
    if actual.base != identity.base || actual.path != identity.path {
        return Err("Gum module identity does not match the requested instance".to_string());
    }
    Ok(owned)
}

fn ensure_initialized(identity: &ModuleIdentity) -> Result<(), String> {
    let module = find_module(identity)?;
    unsafe {
        gum_sys::gum_module_ensure_initialized(module.0);
    }
    Ok(())
}

unsafe extern "C" fn collect_section(
    details: *const gum_sys::GumSectionDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if details.is_null() {
        return 1;
    }
    let details = &*details;
    let Some(id) = optional_string(details.id) else {
        return 1;
    };
    let Some(name) = optional_string(details.name) else {
        return 1;
    };
    (&mut *(user_data as *mut Vec<ModuleSectionDetails>)).push(ModuleSectionDetails {
        id,
        name,
        address: details.address,
        size: details.size as u64,
    });
    1
}

fn enumerate_sections(identity: &ModuleIdentity) -> Result<Vec<ModuleSectionDetails>, String> {
    let module = find_module(identity)?;
    let mut sections = Vec::new();
    unsafe {
        gum_sys::gum_module_enumerate_sections(
            module.0,
            Some(collect_section),
            &mut sections as *mut Vec<ModuleSectionDetails> as *mut _,
        );
    }
    Ok(sections)
}

fn dependency_kind(kind: gum_sys::GumDependencyType) -> &'static str {
    match kind {
        gum_sys::GumDependencyType_GUM_DEPENDENCY_WEAK => "weak",
        gum_sys::GumDependencyType_GUM_DEPENDENCY_REEXPORT => "reexport",
        gum_sys::GumDependencyType_GUM_DEPENDENCY_UPWARD => "upward",
        _ => "regular",
    }
}

unsafe extern "C" fn collect_dependency(
    details: *const gum_sys::GumDependencyDetails,
    user_data: gum_sys::gpointer,
) -> gum_sys::gboolean {
    if details.is_null() {
        return 1;
    }
    let details = &*details;
    let Some(name) = optional_string(details.name) else {
        return 1;
    };
    (&mut *(user_data as *mut Vec<ModuleDependencyDetails>)).push(ModuleDependencyDetails {
        name,
        kind: dependency_kind(details.type_).to_string(),
    });
    1
}

fn enumerate_dependencies(identity: &ModuleIdentity) -> Result<Vec<ModuleDependencyDetails>, String> {
    let module = find_module(identity)?;
    let mut dependencies = Vec::new();
    unsafe {
        gum_sys::gum_module_enumerate_dependencies(
            module.0,
            Some(collect_dependency),
            &mut dependencies as *mut Vec<ModuleDependencyDetails> as *mut _,
        );
    }
    Ok(dependencies)
}

fn find_symbol_by_name(identity: &ModuleIdentity, symbol: &str) -> Result<Option<u64>, String> {
    let module = find_module(identity)?;
    let symbol = c_string(symbol, "symbol name")?;
    let address = unsafe { gum_sys::gum_module_find_symbol_by_name(module.0, symbol.as_ptr()) };
    Ok((address != 0).then_some(address))
}

pub fn install_quickjs_backend() {
    quickjs_hook::install_module_backend(ModuleBackend {
        enumerate_modules,
        ensure_initialized,
        enumerate_sections,
        enumerate_dependencies,
        find_symbol_by_name,
    });
}
