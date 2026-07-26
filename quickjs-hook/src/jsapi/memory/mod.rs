//! Memory API implementation

mod alloc;
mod helpers;
mod monitor;
mod operations;
mod patch;
mod pointers;
mod read;
mod safe_access;
mod scan;
mod scan_async;
mod write;
pub(crate) mod writest;

use crate::context::JSContext;
use crate::jsapi::util::add_cfunction_to_object;

use alloc::*;
pub use monitor::{
    cut_memory_monitor, dispatch_memory_access, install_memory_monitor_backend, MemoryAccessInfo, MemoryMonitorBackend,
};
use operations::*;
use patch::memory_patch_code;
use pointers::{memory_check_code_pointer, memory_find_pointers};
use read::*;
use scan::memory_scan_sync;
use scan_async::memory_scan;
pub use scan_async::{cut_memory_scans, wait_for_memory_scans};
pub(crate) fn safe_read_exact(address: u64, output: &mut [u8]) -> Result<(), String> {
    safe_access::read_exact(address, output).map_err(|error| error.to_string())
}
pub use write::cleanup_wxshadow_patches;
pub(crate) use write::untrack_wxshadow_addr;
use write::*;
pub(crate) use writest::extract_bytes;
use writest::memory_writest;

/// 把 Memory 读写方法注册到 NativePointer prototype，实现 Frida 兼容的
/// `ptr.readXxx()` / `ptr.writeXxx(val)` 调用风格。
pub fn register_ptr_methods(ctx_ptr: *mut crate::ffi::JSContext, proto: crate::ffi::JSValue) {
    unsafe {
        add_cfunction_to_object(ctx_ptr, proto, "readS8", memory_read_s8, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU8", memory_read_u8, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readS16", memory_read_s16, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU16", memory_read_u16, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readS32", memory_read_s32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU32", memory_read_u32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readS64", memory_read_s64, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU64", memory_read_u64, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readShort", memory_read_s16, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readUShort", memory_read_u16, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readInt", memory_read_s32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readUInt", memory_read_u32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readLong", memory_read_s64, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readULong", memory_read_u64, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readFloat", memory_read_float, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readDouble", memory_read_double, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readPointer", memory_read_pointer, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readCString", memory_read_cstring, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readUtf8String", memory_read_utf8_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readUtf16String", memory_read_utf16_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readAnsiString", memory_read_ansi_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readByteArray", memory_read_byte_array, 1);
        add_cfunction_to_object(ctx_ptr, proto, "readVolatile", memory_read_byte_array, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeS8", memory_write_s8, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU8", memory_write_u8, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeS16", memory_write_s16, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU16", memory_write_u16, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeS32", memory_write_s32, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU32", memory_write_u32, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeS64", memory_write_s64, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU64", memory_write_u64, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeShort", memory_write_s16, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeUShort", memory_write_u16, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeInt", memory_write_s32, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeUInt", memory_write_u32, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeLong", memory_write_s64, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeULong", memory_write_u64, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeFloat", memory_write_float, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeDouble", memory_write_double, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writePointer", memory_write_pointer, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeUtf8String", memory_write_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeUtf16String", memory_write_utf16_string, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeAnsiString", memory_write_ansi_string, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeByteArray", memory_write_bytes, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeVolatile", memory_write_volatile, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeBytes", memory_write_bytes, 2);
        add_cfunction_to_object(ctx_ptr, proto, "writest", memory_writest, 1);
    }
}

/// Register Memory API
pub fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = memory.raw();
        add_cfunction_to_object(ctx_ptr, obj, "alloc", memory_alloc, 1);
        add_cfunction_to_object(ctx_ptr, obj, "allocAnsiString", memory_alloc_ansi_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "allocUtf8String", memory_alloc_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "allocUtf16String", memory_alloc_utf16_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "copy", memory_copy, 3);
        add_cfunction_to_object(ctx_ptr, obj, "dup", memory_dup, 2);
        add_cfunction_to_object(ctx_ptr, obj, "flushCodeCache", memory_flush_code_cache, 2);
        add_cfunction_to_object(ctx_ptr, obj, "patchCode", memory_patch_code, 3);
        add_cfunction_to_object(ctx_ptr, obj, "findPointers", memory_find_pointers, 3);
        add_cfunction_to_object(ctx_ptr, obj, "checkCodePointer", memory_check_code_pointer, 1);
        add_cfunction_to_object(ctx_ptr, obj, "queryProtection", memory_query_protection, 1);
        add_cfunction_to_object(ctx_ptr, obj, "scanSync", memory_scan_sync, 3);
        add_cfunction_to_object(ctx_ptr, obj, "scan", memory_scan, 4);
        add_cfunction_to_object(ctx_ptr, obj, "readS8", memory_read_s8, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU8", memory_read_u8, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readS16", memory_read_s16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU16", memory_read_u16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readS32", memory_read_s32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU32", memory_read_u32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readS64", memory_read_s64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU64", memory_read_u64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readShort", memory_read_s16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUShort", memory_read_u16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readInt", memory_read_s32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUInt", memory_read_u32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readLong", memory_read_s64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readULong", memory_read_u64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readFloat", memory_read_float, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readDouble", memory_read_double, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readPointer", memory_read_pointer, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readCString", memory_read_cstring, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUtf8String", memory_read_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUtf16String", memory_read_utf16_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readAnsiString", memory_read_ansi_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readByteArray", memory_read_byte_array, 2);
        add_cfunction_to_object(ctx_ptr, obj, "readVolatile", memory_read_byte_array, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeS8", memory_write_s8, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU8", memory_write_u8, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeS16", memory_write_s16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU16", memory_write_u16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeS32", memory_write_s32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU32", memory_write_u32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeS64", memory_write_s64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU64", memory_write_u64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeShort", memory_write_s16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeUShort", memory_write_u16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeInt", memory_write_s32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeUInt", memory_write_u32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeLong", memory_write_s64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeULong", memory_write_u64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeFloat", memory_write_float, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeDouble", memory_write_double, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writePointer", memory_write_pointer, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeUtf8String", memory_write_utf8_string, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeUtf16String", memory_write_utf16_string, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeAnsiString", memory_write_ansi_string, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeByteArray", memory_write_bytes, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeVolatile", memory_write_volatile, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeBytes", memory_write_bytes, 3);
        add_cfunction_to_object(ctx_ptr, obj, "writest", memory_writest, 2);
        add_cfunction_to_object(ctx_ptr, obj, "protect", memory_protect, 3);
    }

    // Set Memory on global object
    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());

    monitor::register_memory_monitor(ctx);
}

#[cfg(test)]
mod tests {
    use super::register_memory_api;
    use crate::runtime::JSRuntime;

    #[test]
    fn memory_and_native_pointer_work_from_javascript() {
        let runtime = JSRuntime::new().expect("runtime");
        let context = runtime.new_context().expect("context");
        crate::jsapi::ptr::register_ptr(&context);
        register_memory_api(&context);

        let result = context
            .eval(
                r#"
                (() => {
                    const assert = (condition, message) => {
                        if (!condition) throw new Error(message);
                    };

                    const block = Memory.alloc(160);
                    assert(block.writeU8(0xab).equals(block), "write return value");
                    block.add(2).writeU16(0xcdef);
                    block.add(4).writeU32(0x89abcdef);
                    block.add(8).writeU64(0x1122334455667788n);
                    block.add(16).writePointer(block);
                    block.add(24).writeByteArray([0xde, 0xad, 0xbe, 0xef]);
                    block.add(32).writeS8(-2);
                    block.add(34).writeShort(-1234);
                    block.add(36).writeInt(-12345678);
                    block.add(40).writeS64(-0x102030405060708n);
                    block.add(48).writeFloat(1.25);
                    block.add(56).writeDouble(-9.5);
                    assert(block.add(64).writeVolatile(new Uint8Array([1, 2, 3])) === undefined, "writeVolatile");

                    assert(block.readU8() === 0xab, "readU8");
                    assert(block.add(2).readU16() === 0xcdef, "readU16");
                    assert(block.add(4).readU32() === 0x89abcdef, "readU32");
                    assert(block.add(8).readU64() === 0x1122334455667788n, "readU64");
                    assert(block.add(16).readPointer().equals(block), "readPointer");
                    assert(block.add(32).readS8() === -2, "readS8");
                    assert(block.add(34).readShort() === -1234, "readShort");
                    assert(block.add(36).readInt() === -12345678, "readInt");
                    assert(block.add(40).readS64() === -0x102030405060708n, "readS64");
                    assert(block.add(48).readFloat() === 1.25, "readFloat");
                    assert(block.add(56).readDouble() === -9.5, "readDouble");
                    assert(new Uint8Array(block.add(64).readVolatile(3))[2] === 3, "readVolatile");

                    const utf8 = Memory.allocUtf8String("rustfrida-utf8");
                    const utf16 = Memory.allocUtf16String("rustfrida-utf16");
                    assert(utf8.readUtf8String() === "rustfrida-utf8", "UTF-8");
                    assert(utf16.readUtf16String() === "rustfrida-utf16", "UTF-16");

                    const copied = Memory.alloc(4);
                    Memory.copy(copied, block.add(24), 4);
                    const copiedBytes = new Uint8Array(copied.readByteArray(4));
                    assert(Array.prototype.join.call(copiedBytes, ",") === "222,173,190,239", "copy");
                    const duplicated = Memory.dup(block.add(24), 4);
                    assert(duplicated.readU32() === 0xefbeadde, "dup");

                    const matches = Memory.scanSync(block.add(24), 4, "d? ad ?e ef : ff ff ff ff");
                    assert(matches.length === 1, "scan count");
                    assert(matches[0].address.equals(block.add(24)) && matches[0].size === 4, "scan match");
                    assert(Memory.queryProtection(block) === "rw-", "queryProtection");

                    assert(NULL.isNull(), "NULL");
                    assert(ptr("0xff").and(0x0f).equals(ptr("0xf")), "and");
                    assert(ptr("0xf0").or(0x0f).equals(ptr("0xff")), "or");
                    assert(ptr("0xff").xor(0x0f).equals(ptr("0xf0")), "xor");
                    assert(ptr("0x1").shl(4).equals(ptr("0x10")), "shl");
                    assert(ptr("0x10").shr(4).equals(ptr("0x1")), "shr");
                    assert(ptr("0x20").compare(ptr("0x10")) === 1, "compare");
                    assert(ptr("0xff").toString(10) === "255", "radix");
                    assert(block.toMatchPattern().length > 0, "match pattern");

                    let rejected = false;
                    try {
                        ptr("0x1").readU8();
                    } catch (_) {
                        rejected = true;
                    }
                    assert(rejected, "invalid address");
                    return "memory-js-ok";
                })()
                "#,
                "<memory-test>",
            )
            .unwrap_or_else(|error| panic!("JavaScript memory test failed: {error}"));
        assert_eq!(result.to_string(context.as_ptr()).as_deref(), Some("memory-js-ok"));
        result.free(context.as_ptr());
    }
}
