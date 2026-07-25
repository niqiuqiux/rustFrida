//! ptr() function implementation

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Class ID for NativePointer — global (not thread_local) so hook callbacks on
/// arbitrary threads share the same ID and inherit the prototype (toString etc.).
static NATIVE_POINTER_CLASS_ID: AtomicU32 = AtomicU32::new(0);

/// NativePointer class name
const NATIVE_POINTER_CLASS_NAME: &[u8] = b"NativePointer\0";

struct OwnedAllocation {
    addr: u64,
}

impl Drop for OwnedAllocation {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.addr as *mut libc::c_void);
        }
    }
}

struct NativePointerData {
    addr: u64,
    owner: Option<Arc<OwnedAllocation>>,
}

/// Finalizer called by QuickJS GC when a NativePointer object is collected.
/// Derived pointers share the allocation owner, so `Memory.alloc(n).add(k)`
/// remains valid until the last related pointer is collected.
unsafe extern "C" fn native_pointer_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(val, class_id);
    if !opaque.is_null() {
        drop(Box::from_raw(opaque as *mut NativePointerData));
    }
}

/// Get (or allocate + register) the NativePointer class ID on the given runtime.
///
/// Allocation is global (AtomicU32), so all threads share the same class ID.
/// JS_NewClass is called unconditionally — it returns -1 (no-op) if already
/// registered on this runtime.
fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);

    if class_id == 0 {
        // Allocate a globally unique class ID (JS_NewClassID uses a global counter).
        let mut new_id: u32 = 0;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        // CAS: if another thread beat us, use theirs.
        match NATIVE_POINTER_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let rt = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: NATIVE_POINTER_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(native_pointer_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(rt, class_id, &class_def);
    }

    class_id
}

pub(crate) unsafe fn native_pointer_prototype(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    ffi::JS_GetClassProto(ctx, get_or_init_class_id(ctx))
}

fn create_native_pointer_with_owner(
    ctx: *mut ffi::JSContext,
    addr: u64,
    owner: Option<Arc<OwnedAllocation>>,
) -> JSValue {
    let class_id = get_or_init_class_id(ctx);

    unsafe {
        let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);

        // OOM 时 JS_NewObjectClass 返回 JS_EXCEPTION，不能在异常值上调用 JS_SetOpaque
        if ffi::qjs_is_exception(obj) != 0 {
            return JSValue(obj);
        }

        let data = Box::into_raw(Box::new(NativePointerData { addr, owner }));
        ffi::JS_SetOpaque(obj, data as *mut _);

        JSValue(obj)
    }
}

/// Create a non-owning NativePointer object.
pub fn create_native_pointer(ctx: *mut ffi::JSContext, addr: u64) -> JSValue {
    create_native_pointer_with_owner(ctx, addr, None)
}

/// Create a NativePointer that owns a libc allocation.
pub(crate) fn create_owned_native_pointer(ctx: *mut ffi::JSContext, addr: u64) -> JSValue {
    create_native_pointer_with_owner(ctx, addr, Some(Arc::new(OwnedAllocation { addr })))
}

fn clone_native_pointer_parts(_ctx: *mut ffi::JSContext, val: JSValue) -> Option<(u64, Option<Arc<OwnedAllocation>>)> {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return None;
    }

    unsafe {
        let opaque = ffi::JS_GetOpaque(val.raw(), class_id);
        if opaque.is_null() {
            return None;
        }
        let data = &*(opaque as *const NativePointerData);
        Some((data.addr, data.owner.clone()))
    }
}

/// Get address from NativePointer object
pub fn get_native_pointer_addr(_ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    clone_native_pointer_parts(_ctx, val)
        .map(|(addr, _)| addr)
        .or_else(|| crate::jsapi::hook_api::native_callback_address(val.raw()))
        .or_else(|| unsafe { crate::jsapi::hook_api::native_function_address(_ctx, val.raw()) })
}

fn format_native_pointer(addr: u64) -> String {
    format!("0x{:x}", addr)
}

fn native_pointer_as_i32(addr: u64) -> i32 {
    addr as u32 as i32
}

fn native_pointer_as_u32(addr: u64) -> u32 {
    addr as u32
}

unsafe fn parse_pointer_operand(ctx: *mut ffi::JSContext, arg: JSValue, operation: &str) -> Result<u64, ffi::JSValue> {
    if let Some(address) = get_native_pointer_addr(ctx, arg) {
        return Ok(address);
    }
    if arg.is_string() {
        let text = match arg.to_string(ctx) {
            Some(value) => value,
            None => {
                return Err(ffi::JS_ThrowTypeError(
                    ctx,
                    b"invalid pointer string\0".as_ptr() as *const _,
                ))
            }
        };
        let trimmed = text.trim();
        if !trimmed.starts_with("0x") && !trimmed.starts_with("0X") {
            let message = format!("{}: pointer string must be hexadecimal\0", operation);
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"%s\0".as_ptr() as *const _,
                message.as_ptr() as *const libc::c_char,
            ));
        }
        return u64::from_str_radix(&trimmed[2..], 16).map_err(|_| {
            let message = format!("{}: invalid pointer string\0", operation);
            ffi::JS_ThrowTypeError(
                ctx,
                b"%s\0".as_ptr() as *const _,
                message.as_ptr() as *const libc::c_char,
            )
        });
    }
    if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        let mut value = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut value, arg.raw()) == 0 {
            return Ok(value);
        }
    }

    let message = format!("{}: expected a pointer-compatible value\0", operation);
    Err(ffi::JS_ThrowTypeError(
        ctx,
        b"%s\0".as_ptr() as *const _,
        message.as_ptr() as *const libc::c_char,
    ))
}

/// ptr() function implementation
/// Accepts: number, string (hex), BigInt, or NativePointer
unsafe extern "C" fn js_ptr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"ptr() requires 1 argument\0".as_ptr() as *const _);
    }

    let arg = JSValue(*argv);
    let addr: u64;
    let mut owner = None;

    // Check argument type
    if arg.is_string() {
        // Parse hex string
        let s = match arg.to_string(ctx) {
            Some(s) => s,
            None => return ffi::JS_ThrowTypeError(ctx, b"Invalid string\0".as_ptr() as *const _),
        };

        // Remove 0x prefix if present
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");

        addr = match u64::from_str_radix(s, 16) {
            Ok(v) => v,
            Err(_) => return ffi::JS_ThrowTypeError(ctx, b"Invalid hex string\0".as_ptr() as *const _),
        };
    } else if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        // Number or BigInt (hook ctx.thisObj / ctx.args[] / ctx.x0-x30)
        let mut v: u64 = 0;
        if ffi::qjs_value_to_u64(ctx, &mut v, arg.raw()) != 0 {
            return ffi::JS_ThrowTypeError(ctx, b"ptr() failed to convert numeric value\0".as_ptr() as *const _);
        }
        addr = v;
    } else if let Some((ptr_addr, ptr_owner)) = clone_native_pointer_parts(ctx, arg) {
        // Already a NativePointer
        addr = ptr_addr;
        owner = ptr_owner;
    } else {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"ptr() argument must be number, string, or BigInt\0".as_ptr() as *const _,
        );
    }

    create_native_pointer_with_owner(ctx, addr, owner).raw()
}

/// Parse an offset argument for add()/sub() with strict type checking.
/// Accepts: int, float, BigInt, hex string ("0x..."), or NativePointer.
/// Rejects: plain strings, objects, booleans, null, undefined → TypeError.
unsafe fn parse_offset(ctx: *mut ffi::JSContext, arg: JSValue) -> Result<i64, ffi::JSValue> {
    if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        // Number or BigInt — safe to use to_i64
        match arg.to_i64(ctx) {
            Some(v) => Ok(v),
            None => Err(ffi::JS_ThrowTypeError(
                ctx,
                b"failed to convert numeric offset\0".as_ptr() as *const _,
            )),
        }
    } else if arg.is_string() {
        // Only accept hex strings with 0x/0X prefix
        let s = match arg.to_string(ctx) {
            Some(s) => s,
            None => {
                return Err(ffi::JS_ThrowTypeError(
                    ctx,
                    b"invalid string argument\0".as_ptr() as *const _,
                ));
            }
        };
        let trimmed = s.trim();
        if !trimmed.starts_with("0x") && !trimmed.starts_with("0X") {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"string offset must be hex (0x...)\0".as_ptr() as *const _,
            ));
        }
        let hex = &trimmed[2..];
        match u64::from_str_radix(hex, 16) {
            Ok(v) => Ok(v as i64),
            Err(_) => Err(ffi::JS_ThrowTypeError(
                ctx,
                b"invalid hex string\0".as_ptr() as *const _,
            )),
        }
    } else if let Some(ptr_addr) = get_native_pointer_addr(ctx, arg) {
        // NativePointer — use its address as offset
        Ok(ptr_addr as i64)
    } else {
        Err(ffi::JS_ThrowTypeError(
            ctx,
            b"offset must be a number, hex string, or NativePointer\0".as_ptr() as *const _,
        ))
    }
}

/// NativePointer.add() implementation
unsafe extern "C" fn native_pointer_add(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let (addr, owner) = match clone_native_pointer_parts(ctx, this_val) {
        Some(parts) => parts,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"add() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(v) => v,
        Err(exc) => return exc,
    };
    let new_addr = addr.wrapping_add(offset as u64);

    create_native_pointer_with_owner(ctx, new_addr, owner).raw()
}

/// NativePointer.sub() implementation
unsafe extern "C" fn native_pointer_sub(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let (addr, owner) = match clone_native_pointer_parts(ctx, this_val) {
        Some(parts) => parts,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"sub() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(v) => v,
        Err(exc) => return exc,
    };
    let new_addr = addr.wrapping_sub(offset as u64);

    create_native_pointer_with_owner(ctx, new_addr, owner).raw()
}

unsafe extern "C" fn native_pointer_is_null(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(address) => JSValue::bool(address == 0).raw(),
        None => ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    }
}

unsafe extern "C" fn native_pointer_equals(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"equals() requires 1 argument\0".as_ptr() as *const _);
    }
    let other = match parse_pointer_operand(ctx, JSValue(*argv), "equals") {
        Ok(value) => value,
        Err(error) => return error,
    };
    JSValue::bool(address == other).raw()
}

unsafe extern "C" fn native_pointer_compare(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"compare() requires 1 argument\0".as_ptr() as *const _);
    }
    let other = match parse_pointer_operand(ctx, JSValue(*argv), "compare") {
        Ok(value) => value,
        Err(error) => return error,
    };
    JSValue::int(address.cmp(&other) as i32).raw()
}

macro_rules! define_native_pointer_binary_op {
    ($name:ident, $operation:literal, $operator:tt) => {
        unsafe extern "C" fn $name(
            ctx: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (address, owner) = match clone_native_pointer_parts(ctx, JSValue(this)) {
                Some(value) => value,
                None => {
                    return ffi::JS_ThrowTypeError(
                        ctx,
                        b"Not a NativePointer\0".as_ptr() as *const _,
                    )
                }
            };
            if argc < 1 {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    concat!($operation, "() requires 1 argument\0").as_ptr() as *const _,
                );
            }
            let operand = match parse_pointer_operand(ctx, JSValue(*argv), $operation) {
                Ok(value) => value,
                Err(error) => return error,
            };
            create_native_pointer_with_owner(ctx, address $operator operand, owner).raw()
        }
    };
}

define_native_pointer_binary_op!(native_pointer_and, "and", &);
define_native_pointer_binary_op!(native_pointer_or, "or", |);
define_native_pointer_binary_op!(native_pointer_xor, "xor", ^);

unsafe fn native_pointer_shift(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
    left: bool,
) -> ffi::JSValue {
    let (address, owner) = match clone_native_pointer_parts(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    let operation = if left { "shl" } else { "shr" };
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"shift operation requires 1 argument\0".as_ptr() as *const _);
    }
    let amount = match parse_pointer_operand(ctx, JSValue(*argv), operation) {
        Ok(value) => value as u32,
        Err(error) => return error,
    };
    let result = if left {
        address.wrapping_shl(amount)
    } else {
        address.wrapping_shr(amount)
    };
    create_native_pointer_with_owner(ctx, result, owner).raw()
}

unsafe extern "C" fn native_pointer_shl(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    native_pointer_shift(ctx, this, argc, argv, true)
}

unsafe extern "C" fn native_pointer_shr(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    native_pointer_shift(ctx, this, argc, argv, false)
}

unsafe extern "C" fn native_pointer_not(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (address, owner) = match clone_native_pointer_parts(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    create_native_pointer_with_owner(ctx, !address, owner).raw()
}

unsafe extern "C" fn native_pointer_strip(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (address, owner) = match clone_native_pointer_parts(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    let stripped = address & 0x00ff_ffff_ffff_ffff;
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    let stripped = address;
    create_native_pointer_with_owner(ctx, stripped, owner).raw()
}

/// NativePointer.toString() implementation
unsafe extern "C" fn native_pointer_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    let radix = if argc == 0 {
        0
    } else {
        match JSValue(*argv).to_i64(ctx) {
            Some(value) => value,
            None => return ffi::JS_ThrowTypeError(ctx, b"toString(): radix must be an integer\0".as_ptr() as *const _),
        }
    };
    let s = match radix {
        0 => format_native_pointer(addr),
        10 => addr.to_string(),
        16 => format!("{:x}", addr),
        _ => return ffi::JS_ThrowRangeError(ctx, b"toString(): unsupported radix\0".as_ptr() as *const _),
    };
    JSValue::string(ctx, &s).raw()
}

/// NativePointer.toJSON() implementation
unsafe extern "C" fn native_pointer_to_json(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    let s = format_native_pointer(addr);
    JSValue::string(ctx, &s).raw()
}

/// NativePointer.toInt() / toNumber() implementation
unsafe extern "C" fn native_pointer_to_number(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    // Return as BigInt for 64-bit addresses
    ffi::JS_NewBigUint64(ctx, addr)
}

unsafe extern "C" fn native_pointer_to_int32(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let addr = match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(addr) => addr,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    JSValue::int(native_pointer_as_i32(addr)).raw()
}

unsafe extern "C" fn native_pointer_to_uint32(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let addr = match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(addr) => addr,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    ffi::qjs_new_uint32(ctx, native_pointer_as_u32(addr))
}

unsafe extern "C" fn native_pointer_to_match_pattern(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match get_native_pointer_addr(ctx, JSValue(this)) {
        Some(value) => value,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };
    let pattern = (address as usize)
        .to_ne_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(" ");
    JSValue::string(ctx, &pattern).raw()
}

/// Register ptr() function and NativePointer class
pub fn register_ptr(ctx: &JSContext) {
    let class_id = get_or_init_class_id(ctx.as_ptr());

    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();

        // Register ptr() function
        add_cfunction_to_object(ctx_ptr, global.raw(), "ptr", js_ptr, 1);

        // Create NativePointer prototype with methods
        let proto = ffi::JS_NewObject(ctx_ptr);

        add_cfunction_to_object(ctx_ptr, proto, "isNull", native_pointer_is_null, 0);
        add_cfunction_to_object(ctx_ptr, proto, "equals", native_pointer_equals, 1);
        add_cfunction_to_object(ctx_ptr, proto, "add", native_pointer_add, 1);
        add_cfunction_to_object(ctx_ptr, proto, "sub", native_pointer_sub, 1);
        add_cfunction_to_object(ctx_ptr, proto, "and", native_pointer_and, 1);
        add_cfunction_to_object(ctx_ptr, proto, "or", native_pointer_or, 1);
        add_cfunction_to_object(ctx_ptr, proto, "xor", native_pointer_xor, 1);
        add_cfunction_to_object(ctx_ptr, proto, "shr", native_pointer_shr, 1);
        add_cfunction_to_object(ctx_ptr, proto, "shl", native_pointer_shl, 1);
        add_cfunction_to_object(ctx_ptr, proto, "not", native_pointer_not, 0);
        add_cfunction_to_object(ctx_ptr, proto, "strip", native_pointer_strip, 0);
        add_cfunction_to_object(ctx_ptr, proto, "compare", native_pointer_compare, 1);
        add_cfunction_to_object(ctx_ptr, proto, "toString", native_pointer_to_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toJSON", native_pointer_to_json, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toMatchPattern", native_pointer_to_match_pattern, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toNumber", native_pointer_to_number, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toInt", native_pointer_to_number, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toInt32", native_pointer_to_int32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toUInt32", native_pointer_to_uint32, 0);

        // Frida 兼容: 注册 Memory 读写方法到 NativePointer prototype
        // 支持 ptr.readU32() / ptr.writeU32(val) 调用风格
        crate::jsapi::memory::register_ptr_methods(ctx_ptr, proto);

        // Set as class prototype
        let ctor = ffi::JS_NewCFunction2(
            ctx_ptr,
            Some(js_ptr),
            b"NativePointer\0".as_ptr() as *const _,
            1,
            ffi::JSCFunctionEnum_JS_CFUNC_constructor_or_func,
            0,
        );
        ffi::JS_SetConstructor(ctx_ptr, ctor, proto);
        global.set_property(ctx_ptr, "NativePointer", JSValue(ctor));
        ffi::JS_SetClassProto(ctx_ptr, class_id, proto);

        global.set_property(ctx_ptr, "NULL", create_native_pointer(ctx_ptr, 0));
    }

    global.free(ctx.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::{format_native_pointer, native_pointer_as_i32, native_pointer_as_u32};

    #[test]
    fn formats_native_pointer_as_hex_string() {
        assert_eq!(format_native_pointer(0x1234_abcd), "0x1234abcd");
    }

    #[test]
    fn truncates_native_pointer_to_32_bits() {
        assert_eq!(native_pointer_as_i32(0xffff_ffff), -1);
        assert_eq!(native_pointer_as_u32(0xffff_ffff), u32::MAX);
        assert_eq!(native_pointer_as_i32(0x1_0000_0001), 1);
        assert_eq!(native_pointer_as_u32(0x1_0000_0001), 1);
    }
}
