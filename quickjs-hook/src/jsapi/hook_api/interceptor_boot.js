// Interceptor — Frida-compatible API.
//
// 核心 attach/replace/detachAll/flush 已由 Rust 侧注册为 CFunction。
// 本文件仅补充 JS 层的 args/retval 代理和 __interceptorEnter/__interceptorLeave helper。
//
// 用法（与 Frida 完全一致）：
//   var listener = Interceptor.attach(addr, {
//       onEnter(args) {
//           // args[0..7] = x0..x7 (NativePointer)
//           console.log('open(' + args[0].readCString() + ')');
//           this.path = args[0].readCString();    // 跨阶段共享
//       },
//       onLeave(retval) {
//           console.log(this.path + ' => fd=' + retval.toInt32());
//           if (retval.toInt32() < 0) retval.replace(0);
//       }
//   });
//   listener.detach();
//
//   Interceptor.replace(addr, function(a, b) { return a + b; });
//   Interceptor.detachAll();
(function() {
    "use strict";

    // The native engine deliberately owns every target itself; defaults only
    // select its rustFrida stealth mode when a call does not supply one.
    const nativeAttach = Interceptor.attach;
    const nativeReplace = Interceptor.replace;
    const nativeReplaceFast = Interceptor.replaceFast;
    let defaults = {};

    function defaultMode(explicitMode) {
        if (explicitMode !== undefined)
            return explicitMode;
        if (defaults.mode !== undefined)
            return defaults.mode;
        return defaults.stealth;
    }

    Object.defineProperties(Interceptor, {
        defaults: {
            enumerable: true,
            get() { return defaults; },
            set(value) {
                if (value === null || typeof value !== "object")
                    throw new TypeError("Interceptor.defaults must be an object");
                if (value.mode !== undefined && value.stealth !== undefined)
                    throw new TypeError("Interceptor.defaults must specify either mode or stealth");
                defaults = value;
            }
        },
        attach: {
            enumerable: true,
            value(target, callbacks, mode) {
                const resolvedMode = defaultMode(mode);
                return resolvedMode === undefined
                    ? nativeAttach(target, callbacks)
                    : nativeAttach(target, callbacks, resolvedMode);
            }
        },
        replace: {
            enumerable: true,
            value(target, replacement, mode) {
                const resolvedMode = defaultMode(mode);
                return resolvedMode === undefined
                    ? nativeReplace(target, replacement)
                    : nativeReplace(target, replacement, resolvedMode);
            }
        },
        replaceFast: {
            enumerable: true,
            value(target, replacement, mode) {
                const resolvedMode = defaultMode(mode);
                return resolvedMode === undefined
                    ? nativeReplaceFast(target, replacement)
                    : nativeReplaceFast(target, replacement, resolvedMode);
            }
        }
    });

    function _toBigInt(v) {
        if (v === null || v === undefined) return 0n;
        if (typeof v === 'bigint') return v;
        if (typeof v === 'number') return BigInt(Math.trunc(v));
        if (typeof v === 'boolean') return v ? 1n : 0n;
        if (typeof v === 'string') {
            try { return BigInt(v); } catch (e) { return 0n; }
        }
        if (typeof v === 'object') {
            // NativePointer / 其它自定义对象：取 toString() -> "0x..."
            if (typeof v.toString === 'function') {
                try {
                    var s = v.toString();
                    if (typeof s === 'string') {
                        if (s.indexOf('0x') === 0 || s.indexOf('0X') === 0) return BigInt(s);
                        if (/^-?\d+$/.test(s)) return BigInt(s);
                    }
                } catch (e) { /* fall through */ }
            }
            if (typeof v.valueOf === 'function') {
                try {
                    var vv = v.valueOf();
                    if (typeof vv === 'bigint') return vv;
                    if (typeof vv === 'number') return BigInt(Math.trunc(vv));
                } catch (e) { /* ignore */ }
            }
        }
        return 0n;
    }

    // args[N] ⇄ ctx.xN。读返回 NativePointer，写接受 Number / BigInt / NativePointer。
    function _makeArgsProxy(ctx) {
        return new Proxy({}, {
            get: function(_, key) {
                if (key === Symbol.toPrimitive) return function() { return 0; };
                if (typeof key === 'symbol') return undefined;
                var i = Number(key);
                if (!Number.isFinite(i) || i < 0 || i > 30) return undefined;
                var v = ctx['x' + i];
                return (typeof ptr === 'function') ? ptr(v) : v;
            },
            set: function(_, key, value) {
                var i = Number(key);
                if (!Number.isFinite(i) || i < 0 || i > 30) return false;
                ctx['x' + i] = _toBigInt(value);
                return true;
            }
        });
    }

    // retval 包装：NativePointer-like，带 .replace() / .toInt32() / .toUInt32()
    // replace() 写回 ctx.x0；toInt32/toUInt32 每次读 ctx.x0 反映最新状态
    function _makeRetval(ctx) {
        var wrap;
        if (typeof ptr === 'function') {
            wrap = ptr(ctx.x0);
        } else {
            wrap = Object.create(null);
        }
        wrap.replace = function(v) { ctx.x0 = _toBigInt(v); };
        wrap.toInt32 = function() {
            var v = ctx.x0;
            var b = (typeof v === 'bigint') ? v : BigInt(v || 0);
            return Number(BigInt.asIntN(32, b));
        };
        wrap.toUInt32 = function() {
            var v = ctx.x0;
            var b = (typeof v === 'bigint') ? v : BigInt(v || 0);
            return Number(BigInt.asUintN(32, b));
        };
        return wrap;
    }

    // Rust 侧在 JS 锁内调这两个 helper。调用签名固定：helper(userFn, ctx)。
    // 异常已由 Rust 侧的 handle_js_exception 捕获并打印，此处 try/catch 是双保险。
    globalThis.__interceptorEnter = function(userFn, ctx) {
        try {
            var args = _makeArgsProxy(ctx);
            userFn.call(ctx, args);
        } catch (e) {
            var msg = (e && e.stack) ? e.stack : String(e);
            if (typeof console !== 'undefined' && console.log) console.log('[Interceptor onEnter] ' + msg);
        }
    };

    globalThis.__interceptorLeave = function(userFn, ctx) {
        try {
            var retval = _makeRetval(ctx);
            userFn.call(ctx, retval);
        } catch (e) {
            var msg = (e && e.stack) ? e.stack : String(e);
            if (typeof console !== 'undefined' && console.log) console.log('[Interceptor onLeave] ' + msg);
        }
    };
})();
