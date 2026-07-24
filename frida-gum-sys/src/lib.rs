/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

#[inline]
pub unsafe fn gum_rs_interceptor_attach(
    interceptor: *mut GumInterceptor,
    function: gpointer,
    listener: *mut GumInvocationListener,
) -> GumAttachReturn {
    #[cfg(frida_gum_modern_interceptor)]
    {
        gum_interceptor_attach(interceptor, function, listener, core::ptr::null())
    }
    #[cfg(not(frida_gum_modern_interceptor))]
    {
        gum_interceptor_attach(interceptor, function, listener, core::ptr::null_mut(), 0)
    }
}

/// Drop Gum interceptor contexts in a range without restoring unmapped code.
/// Fixed local devkits link the helper directly; older release devkits use a
/// weak C bridge that safely becomes a no-op.
#[inline]
pub unsafe fn gum_rs_interceptor_discard_hooks_in_range(range: *const GumMemoryRange) {
    #[cfg(all(feature = "invocation-listener", frida_gum_interceptor_discard))]
    _gum_interceptor_forget_all_hooks_in_range(range);
    #[cfg(all(feature = "invocation-listener", not(frida_gum_interceptor_discard)))]
    gum_rs_interceptor_discard_hooks_in_range_c(range);
}

#[cfg(all(feature = "invocation-listener", frida_gum_interceptor_discard))]
extern "C" {
    fn _gum_interceptor_forget_all_hooks_in_range(range: *const GumMemoryRange);
}

#[cfg(all(feature = "invocation-listener", not(frida_gum_interceptor_discard)))]
extern "C" {
    fn gum_rs_interceptor_discard_hooks_in_range_c(range: *const GumMemoryRange);
}

#[inline]
pub unsafe fn gum_rs_interceptor_replace(
    interceptor: *mut GumInterceptor,
    function: gpointer,
    replacement: gpointer,
    replacement_data: gpointer,
    original: *mut gpointer,
) -> GumReplaceReturn {
    #[cfg(frida_gum_modern_interceptor)]
    {
        let mut options: GumReplaceOptions = core::mem::zeroed();
        options.replacement_data = replacement_data;
        gum_interceptor_replace(interceptor, function, replacement, original, &options)
    }
    #[cfg(not(frida_gum_modern_interceptor))]
    {
        gum_interceptor_replace(interceptor, function, replacement, replacement_data, original)
    }
}

#[inline]
pub unsafe fn gum_rs_interceptor_replace_fast(
    interceptor: *mut GumInterceptor,
    function: gpointer,
    replacement: gpointer,
    original: *mut gpointer,
) -> GumReplaceReturn {
    #[cfg(frida_gum_modern_interceptor)]
    {
        gum_interceptor_replace_fast(interceptor, function, replacement, original, core::ptr::null())
    }
    #[cfg(not(frida_gum_modern_interceptor))]
    {
        gum_interceptor_replace_fast(interceptor, function, replacement, original)
    }
}

#[inline]
pub unsafe fn gum_rs_stalker_activate_experimental_unwind_support() {
    #[cfg(frida_gum_modern_interceptor)]
    {
        // Gum's unwind broker makes generated-code translation always-on.
    }
    #[cfg(not(frida_gum_modern_interceptor))]
    {
        gum_stalker_activate_experimental_unwind_support();
    }
}

#[cfg(not(any(target_os = "windows", target_vendor = "apple",)))]
pub use {_frida_g_object_ref as g_object_ref, _frida_g_object_unref as g_object_unref};

/// A single disassembled CPU instruction.
#[repr(transparent)]
pub struct Insn {
    /// Inner `cs_insn`
    pub insn: cs_insn,
}

#[allow(clippy::len_without_is_empty)]
impl Insn {
    /// Create an `Insn` from a raw pointer to a [`capstone_sys::cs_insn`].
    ///
    /// This function serves to allow integration with libraries which generate `capstone_sys::cs_insn`'s internally.
    ///
    /// # Safety
    ///
    /// Note that this function is unsafe, and assumes that you know what you are doing. In
    /// particular, it generates a lifetime for the `Insn` from nothing, and that lifetime is in
    /// no-way actually tied to the cs_insn itself. It is the responsibility of the caller to
    /// ensure that the resulting `Insn` lives only as long as the `cs_insn`. This function
    /// assumes that the pointer passed is non-null and a valid `cs_insn` pointer.
    ///
    /// The caller is fully responsible for the backing allocations lifetime, including freeing.
    pub unsafe fn from_raw(insn: *const cs_insn) -> Self {
        Self {
            insn: core::ptr::read(insn),
        }
    }

    /// Size of instruction (in bytes)
    #[inline]
    #[allow(clippy::unnecessary_cast)]
    pub fn len(&self) -> usize {
        self.insn.size as usize
    }

    /// Instruction address
    #[inline]
    #[allow(clippy::unnecessary_cast)]
    pub fn address(&self) -> u64 {
        self.insn.address as u64
    }

    /// Byte-level representation of the instruction
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.insn.bytes[..self.len()]
    }
}
