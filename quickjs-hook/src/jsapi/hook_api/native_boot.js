// NativeFunction — Frida-compatible native function calling.
//
// Usage (identical to Frida):
//   var open = new NativeFunction(
//       Module.findExportByName('libc.so', 'open'),
//       'int',                            // return type
//       ['pointer', 'int']                // arg types
//   );
//   var fd = open(Memory.allocUtf8String('/tmp/foo'), 0);
//   close(fd);
//
//   var atan2 = new NativeFunction(
//       Module.findExportByName('libm.so', 'atan2'),
//       'double',
//       ['double', 'double']
//   );
//   var r = atan2(1.0, 2.0);
//
// Type strings supported:
//   'void'
//   'bool'   (1 byte bool)
//   'char', 'uchar', 'int8', 'uint8'
//   'short', 'ushort', 'int16', 'uint16'
//   'int', 'uint', 'int32', 'uint32'
//   'long', 'ulong'          (64-bit on ARM64 Android)
//   'int64', 'uint64'
//   'size_t', 'ssize_t'
//   'pointer'
//   'float', 'double'
//
// AAPCS64 calling convention:
//   - Integer/pointer args fill x0..x7 in order (queue A)
//   - Float/double args fill d0..d7 in order (queue B)
//   - Queues are INDEPENDENT: `void f(int a, float b, int c)` →
//     a=x0, c=x1, b=d0
//   - Return: int/pointer in x0, float/double in d0
//
// Scalar fallback limits (builds without the `frida-ffi` feature):
//   - Integer/pointer args: x0-x7, overflow spills to stack
//   - Float/double args:   d0-d7, overflow spills to stack
//   - Max 256 stack-spilled args (2KB stack region)
// Agent builds enable `frida-ffi`, which additionally supports variadic calls
// and nested struct-by-value arguments and return values.

// hook(addr, fn, stealth?) — Frida 风格回调包装
//   fn(arg0, arg1, ..., arg7) { this.x0, this.$orig(), ... }
//   固定执行原函数的场景用 Interceptor.attach；hook()/$orig() 只用于条件性调用或替换。
//     arguments[0..7] = x0..x7 (ARM64 ABI 前 8 个整型参数)
//     this = register context，含 x0-x30 / sp / pc / $orig() / trampoline
//   recompHook 同样处理。
(function() {
    "use strict";
    if (typeof hook !== 'function') return;
    var _hook = hook;
    var _recompHook = (typeof recompHook === 'function') ? recompHook : null;
    function _wrapNativeCallback(userFn) {
        return function(ctx) {
            return userFn.apply(ctx, [
                ctx.x0, ctx.x1, ctx.x2, ctx.x3,
                ctx.x4, ctx.x5, ctx.x6, ctx.x7
            ]);
        };
    }
    globalThis.hook = function(addr, fn, stealth) {
        if (typeof fn !== 'function') {
            return (arguments.length >= 3) ? _hook(addr, fn, stealth) : _hook(addr, fn);
        }
        var wrapped = _wrapNativeCallback(fn);
        return (arguments.length >= 3) ? _hook(addr, wrapped, stealth) : _hook(addr, wrapped);
    };
    if (_recompHook) {
        globalThis.recompHook = function(addr, fn) {
            if (typeof fn !== 'function') return _recompHook(addr, fn);
            return _recompHook(addr, _wrapNativeCallback(fn));
        };
    }
})();

(function() {
    "use strict";

    // Type classification:
    //   kind: 0 = void (return only), 1 = int (goes to GPR), 2 = float (goes to FPR)
    var TYPE_INFO = {
        'void':    { kind: 0, size: 0 },
        'bool':    { kind: 1, size: 1, isBool: true },
        'char':    { kind: 1, size: 1, sign: true  },
        'uchar':   { kind: 1, size: 1, sign: false },
        'int8':    { kind: 1, size: 1, sign: true  },
        'uint8':   { kind: 1, size: 1, sign: false },
        'short':   { kind: 1, size: 2, sign: true  },
        'ushort':  { kind: 1, size: 2, sign: false },
        'int16':   { kind: 1, size: 2, sign: true  },
        'uint16':  { kind: 1, size: 2, sign: false },
        'int':     { kind: 1, size: 4, sign: true  },
        'uint':    { kind: 1, size: 4, sign: false },
        'int32':   { kind: 1, size: 4, sign: true  },
        'uint32':  { kind: 1, size: 4, sign: false },
        'long':    { kind: 1, size: 8, sign: true  },  // ARM64 Android: 64-bit
        'ulong':   { kind: 1, size: 8, sign: false },
        'int64':   { kind: 1, size: 8, sign: true  },
        'uint64':  { kind: 1, size: 8, sign: false },
        'size_t':  { kind: 1, size: 8, sign: false },
        'ssize_t': { kind: 1, size: 8, sign: true  },
        'pointer': { kind: 1, size: 8, sign: false, isPtr: true },
        'float':   { kind: 2, size: 4 },
        'double':  { kind: 2, size: 8 }
    };

    function _resolveType(name) {
        if (typeof name !== 'string') {
            throw new TypeError("NativeFunction: type must be a string, got " + typeof name);
        }
        var info = TYPE_INFO[name];
        if (!info) {
            throw new TypeError("NativeFunction: unknown type '" + name + "'");
        }
        return info;
    }

    function _coerceArgInt(val, type) {
        if (val === null || val === undefined) return 0n;
        if (typeof val === 'bigint') return val;
        if (typeof val === 'boolean') return val ? 1n : 0n;
        if (typeof val === 'number') {
            // 整数 Number → BigInt；浮点 Number → 截断到整数
            return BigInt(Math.trunc(val));
        }
        if (typeof val === 'string') {
            // "0x..." 十六进制 or 十进制
            try { return BigInt(val); } catch (e) { return 0n; }
        }
        // object: NativePointer 或其它
        //   NativePointer 走 .toString() → "0x..." → BigInt
        //   注意底层 js_native_call 会用 js_value_to_u64_or_zero 解析，
        //   但那个函数对 NativePointer 可能不认，所以这里先显式转成 BigInt
        if (typeof val === 'object') {
            if (typeof val.toString === 'function') {
                try {
                    var s = val.toString();
                    if (typeof s === 'string') {
                        // NativePointer.toString() 返回 "0x..."
                        if (s.indexOf('0x') === 0 || s.indexOf('0X') === 0) {
                            return BigInt(s);
                        }
                        // 纯数字字符串
                        if (/^-?\d+$/.test(s)) return BigInt(s);
                    }
                } catch (e) { /* fall through */ }
            }
            if (typeof val.valueOf === 'function') {
                try {
                    var v = val.valueOf();
                    if (typeof v === 'number') return BigInt(Math.trunc(v));
                    if (typeof v === 'bigint') return v;
                } catch (e) { /* fall through */ }
            }
            return 0n;
        }
        return 0n;
    }

    function _coerceArgFloat(val) {
        if (val === null || val === undefined) return 0.0;
        if (typeof val === 'number') return val;
        if (typeof val === 'bigint') return Number(val);
        if (typeof val === 'boolean') return val ? 1.0 : 0.0;
        if (typeof val === 'string') return parseFloat(val);
        return 0.0;
    }

    function _coerceReturnInt(raw, type) {
        // raw 是 BigInt 或 Number (js_i64_to_js_number_or_bigint 返回)
        // 统一成 BigInt 做位运算
        var n;
        if (typeof raw === 'bigint') {
            n = raw;
        } else if (typeof raw === 'number') {
            // Number 可能是负数（i64 高位），先 unsigned 化
            if (raw < 0) {
                n = BigInt(raw) + (1n << 64n);
            } else {
                n = BigInt(Math.trunc(raw));
            }
        } else {
            return raw;
        }
        // bool: 非零即 true (只看低 8 bits)
        if (type.isBool) {
            return (n & 0xFFn) !== 0n;
        }
        // 按类型做符号扩展和大小截断
        switch (type.size) {
            case 1: {
                var v = Number(n & 0xFFn);
                return type.sign && v >= 0x80 ? v - 0x100 : v;
            }
            case 2: {
                var v = Number(n & 0xFFFFn);
                return type.sign && v >= 0x8000 ? v - 0x10000 : v;
            }
            case 4: {
                var v = Number(n & 0xFFFFFFFFn);
                return type.sign && v >= 0x80000000 ? v - 0x100000000 : v;
            }
            case 8: {
                // 64-bit: pointer → NativePointer wrapper (通过 ptr())
                //          long/ulong/int64/uint64/size_t → BigInt
                if (type.isPtr) {
                    var addr64 = BigInt.asUintN(64, n);
                    if (addr64 === 0n) return null;  // NULL pointer
                    // 用 BigInt 直接调 ptr，避免字符串往返
                    try {
                        return (typeof ptr === 'function') ? ptr(addr64) : addr64;
                    } catch (e) {
                        return addr64;  // ptr() 失败就返回裸 BigInt
                    }
                }
                if (type.sign) return BigInt.asIntN(64, n);
                return BigInt.asUintN(64, n);
            }
            default:
                return Number(n);
        }
    }

    // 把一个 f32 值转成 u64 bit 图（低 32 bits = f32 bits，高 32 bits = 0）
    // 用于 stack spill 时把 float 参数塞进 8 字节槽
    var _f32Ab = new ArrayBuffer(4);
    var _f32View = new Float32Array(_f32Ab);
    var _f32Bits = new Uint32Array(_f32Ab);
    function _floatBitsAsU64(val) {
        _f32View[0] = val;
        return BigInt(_f32Bits[0]);  // 只填低 32 bits，高位自动为 0
    }

    // 把一个 f64 值转成 u64 bit 图（完整 64 bits）
    var _f64Ab = new ArrayBuffer(8);
    var _f64View = new Float64Array(_f64Ab);
    var _f64Bits = new BigUint64Array(_f64Ab);
    function _doubleBitsAsU64(val) {
        _f64View[0] = val;
        return _f64Bits[0];
    }

    function _parseNativeOptions(apiName, value) {
        var options = {
            abi: 'default',
            scheduling: 'cooperative',
            exceptions: 'steal',
            traps: 'default'
        };
        if (value === undefined || value === null) return options;
        if (typeof value === 'string') {
            options.abi = value;
        } else if (typeof value === 'object') {
            if (value.abi !== undefined) options.abi = value.abi;
            if (value.scheduling !== undefined) options.scheduling = value.scheduling;
            if (value.exceptions !== undefined) options.exceptions = value.exceptions;
            if (value.traps !== undefined) options.traps = value.traps;
        } else {
            throw new TypeError(apiName + ': expected ABI string or options object');
        }
        if (options.abi !== 'default' && options.abi !== 'sysv') {
            throw new TypeError(apiName + ': unsupported ABI on ARM64 Android');
        }
        if (options.scheduling !== 'cooperative' && options.scheduling !== 'exclusive') {
            throw new TypeError(apiName + ': scheduling must be cooperative or exclusive');
        }
        if (options.exceptions !== 'steal' && options.exceptions !== 'propagate') {
            throw new TypeError(apiName + ': exceptions must be steal or propagate');
        }
        if (options.traps !== 'default' && options.traps !== 'none' && options.traps !== 'all') {
            throw new TypeError(apiName + ': traps must be default, none, or all');
        }
        return options;
    }

    function _validateReceiver(apiName, receiver) {
        if (receiver === null || receiver === undefined) return null;
        if (typeof receiver !== 'object' && typeof receiver !== 'function') {
            throw new TypeError(apiName + ': invalid receiver');
        }
        return receiver;
    }

    function _toArgumentArray(apiName, values) {
        if (values === null || values === undefined) return [];
        if (typeof values !== 'object' && typeof values !== 'function') {
            throw new TypeError(apiName + '.apply: expected an array-like value');
        }
        var length = Number(values.length);
        if (!Number.isSafeInteger(length) || length < 0) {
            throw new TypeError(apiName + '.apply: invalid array-like length');
        }
        var result = new Array(length);
        for (var i = 0; i < length; i++) result[i] = values[i];
        return result;
    }

    function _installNativeFunctionPrototype(constructor, parentPrototype, apiName) {
        var prototype = Object.create(parentPrototype);
        Object.defineProperties(prototype, {
            constructor: { value: constructor, writable: true, configurable: true },
            call: {
                value: function(receiver) {
                    var args = new Array(Math.max(arguments.length - 1, 0));
                    for (var i = 1; i < arguments.length; i++) args[i - 1] = arguments[i];
                    return this.__rfNativeFunctionInvoke(_validateReceiver(apiName, receiver), args);
                },
                writable: true,
                configurable: true
            },
            apply: {
                value: function(receiver, args) {
                    return this.__rfNativeFunctionInvoke(
                        _validateReceiver(apiName, receiver),
                        _toArgumentArray(apiName, args)
                    );
                },
                writable: true,
                configurable: true
            }
        });
        constructor.prototype = prototype;
    }

    // NativeFunction/SystemFunction 构造器 — 返回可调用的 NativePointer 子类实例。
    function _makeNativeFunction(apiName, addr, retType, argTypes, optionValue, captureSystemError, prototype) {
        if (addr === null || addr === undefined) {
            throw new TypeError(apiName + ": addr must not be null");
        }
        if (!Array.isArray(argTypes)) {
            throw new TypeError(apiName + ": argTypes must be an array");
        }
        var options = _parseNativeOptions(apiName, optionValue);
        var useFfi = typeof __nativeFfiPrepare === 'function' && typeof __nativeFfiCall === 'function';
        var ffiSignature = useFfi ? __nativeFfiPrepare(retType, argTypes) : null;

        if (!useFfi && (options.scheduling !== 'cooperative'
                || options.exceptions !== 'steal' || options.traps === 'all')) {
            throw new TypeError(apiName + ': requested options require Frida FFI support');
        }

        if (useFfi) {
            function invokeFfi(implementation, values) {
                var trapMode = options.traps === 'none' ? 1 : (options.traps === 'all' ? 2 : 0);
                return __nativeFfiCall(
                    ffiSignature,
                    implementation === null ? addr : implementation,
                    values,
                    captureSystemError,
                    options.scheduling === 'cooperative',
                    options.exceptions === 'steal',
                    trapMode
                );
            }
            return _createNativeFunctionObject(
                apiName, addr, retType, argTypes, options, prototype, invokeFfi
            );
        }

        var retInfo = _resolveType(retType);
        var argInfos = argTypes.map(_resolveType);

        // 预计算每个参数应该去哪里：
        //   slot: 寄存器槽位 0-7 (register) 或 -1 (stack spill)
        //   argPlan[i] = { slot, kind, info }
        var argPlan = new Array(argInfos.length);
        var gprCount = 0, fprCount = 0;
        var precomputedFloat32Mask = 0;
        var stackArgCount = 0;
        for (var i = 0; i < argInfos.length; i++) {
            var info = argInfos[i];
            if (info.kind === 0) {
                throw new TypeError(apiName + ": 'void' can only be the return type");
            }
            if (info.kind === 1) {
                // 整数：先填 x0-x7，满了就溢出到栈
                if (gprCount < 8) {
                    argPlan[i] = { slot: gprCount, kind: 1, info: info };
                    gprCount++;
                } else {
                    argPlan[i] = { slot: -1, kind: 1, info: info };
                    stackArgCount++;
                }
            } else {
                // 浮点：先填 d0-d7，满了就溢出
                if (fprCount < 8) {
                    argPlan[i] = { slot: fprCount, kind: 2, info: info };
                    if (info.size === 4) {
                        precomputedFloat32Mask |= (1 << fprCount);
                    }
                    fprCount++;
                } else {
                    argPlan[i] = { slot: -1, kind: 2, info: info };
                    stackArgCount++;
                }
            }
        }
        if (stackArgCount > 256) {
            throw new RangeError(apiName + ": too many args (" + argInfos.length + " total, " + stackArgCount + " stack overflow > 256)");
        }

        // retKind: 0=void, 1=int, 2=double(f64), 3=float32
        var retKind;
        if (retInfo.kind === 0) retKind = 0;
        else if (retInfo.kind === 1) retKind = 1;
        else if (retInfo.kind === 2 && retInfo.size === 4) retKind = 3;
        else retKind = 2;

        function invoke(implementation, values) {
            if (values.length !== argInfos.length) {
                throw new TypeError(apiName + ": expected " + argInfos.length + " args, got " + values.length);
            }
            var gpr = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
            var fpr = [0, 0, 0, 0, 0, 0, 0, 0];
            var stk = [];  // 栈溢出参数，u64 bit 图（BigInt）按声明顺序
            for (var i = 0; i < argInfos.length; i++) {
                var plan = argPlan[i];
                var val = values[i];
                var info = plan.info;
                if (plan.slot !== -1) {
                    // 寄存器参数
                    if (plan.kind === 1) {
                        gpr[plan.slot] = _coerceArgInt(val, info);
                    } else {
                        fpr[plan.slot] = _coerceArgFloat(val);
                    }
                } else {
                    // 栈参数：统一转成 u64 bit 图
                    if (plan.kind === 1) {
                        stk.push(_coerceArgInt(val, info));
                    } else if (info.size === 4) {
                        stk.push(_floatBitsAsU64(_coerceArgFloat(val)));
                    } else {
                        stk.push(_doubleBitsAsU64(_coerceArgFloat(val)));
                    }
                }
            }
            var result = __nativeCall(
                implementation === null ? addr : implementation,
                retKind,
                gpr,
                fpr,
                precomputedFloat32Mask,
                stk,
                captureSystemError,
                options.traps !== 'none'
            );
            var raw = captureSystemError ? result.value : result;
            var value;
            if (retKind === 0) value = undefined;
            else if (retKind === 2 || retKind === 3) value = raw;
            else value = _coerceReturnInt(raw, retInfo);
            if (captureSystemError) return { value: value, errno: result.errno };
            return value;
        }

        return _createNativeFunctionObject(
            apiName, addr, retType, argTypes, options, prototype, invoke
        );
    }

    function _createNativeFunctionObject(apiName, addr, retType, argTypes, options, prototype, invoke) {
        var fn = function() {
            var values = new Array(arguments.length);
            for (var i = 0; i < arguments.length; i++) values[i] = arguments[i];
            return invoke(null, values);
        };
        Object.setPrototypeOf(fn, prototype);

        // 暴露元信息方便调试
        Object.defineProperties(fn, {
            __rfNativeFunctionAddress: { value: _coerceArgInt(addr, TYPE_INFO.pointer) },
            __rfNativeFunctionInvoke: { value: invoke },
            address: { value: addr, enumerable: true },
            returnType: { value: retType, enumerable: true },
            argumentTypes: { value: argTypes.slice(), enumerable: true },
            abi: { value: options.abi, enumerable: true }
        });
        return fn;
    }

    function NativeFunction(addr, retType, argTypes, options) {
        return _makeNativeFunction(
            'NativeFunction', addr, retType, argTypes, options, false, NativeFunction.prototype
        );
    }

    function SystemFunction(addr, retType, argTypes, options) {
        return _makeNativeFunction(
            'SystemFunction', addr, retType, argTypes, options, true, SystemFunction.prototype
        );
    }

    _installNativeFunctionPrototype(NativeFunction, NativePointer.prototype, 'NativeFunction');
    _installNativeFunctionPrototype(SystemFunction, NativePointer.prototype, 'SystemFunction');
    globalThis.NativeFunction = NativeFunction;
    globalThis.SystemFunction = SystemFunction;
})();
