(function () {
    "use strict";

    const state = new WeakMap();
    const modulus = 1n << 64n;
    const signBit = 1n << 63n;

    function normalizeUnsigned(value) {
        const result = value % modulus;
        return result < 0n ? result + modulus : result;
    }

    function normalizeSigned(value) {
        const result = normalizeUnsigned(value);
        return result >= signBit ? result - modulus : result;
    }

    function parse(value, signed) {
        let result;
        if (value !== null && (typeof value === "object" || typeof value === "function") && state.has(value)) {
            result = state.get(value);
        } else if (typeof value === "bigint") {
            result = value;
        } else if (typeof value === "number") {
            if (!Number.isFinite(value))
                throw new TypeError(signed ? "expected an integer" : "expected an unsigned integer");
            if (!signed && value < 0)
                throw new TypeError("expected an unsigned integer");
            result = BigInt(Math.trunc(value));
        } else if (typeof value === "string") {
            try {
                result = BigInt(value);
            } catch (_) {
                throw new TypeError(signed ? "expected an integer" : "expected an unsigned integer");
            }
        } else {
            throw new TypeError(signed ? "expected an integer" : "expected an unsigned integer");
        }
        return signed ? normalizeSigned(result) : normalizeUnsigned(result);
    }

    function requireRadix(radix) {
        if (radix === undefined)
            return 10;
        const value = Number(radix) >>> 0;
        if (value !== 10 && value !== 16)
            throw new Error("unsupported radix");
        return value;
    }

    function define(name, signed) {
        const normalize = signed ? normalizeSigned : normalizeUnsigned;

        const Wrapper = function (value) {
            if (!new.target)
                throw new TypeError("class constructor must be invoked with 'new'");
            state.set(this, parse(value, signed));
        };
        Object.defineProperty(Wrapper, "name", { value: name });

        function unwrap(instance) {
            if (!state.has(instance))
                throw new TypeError("invalid receiver");
            return state.get(instance);
        }

        const methods = {
            add(rhs) { return new Wrapper(normalize(unwrap(this) + parse(rhs, signed))); },
            sub(rhs) { return new Wrapper(normalize(unwrap(this) - parse(rhs, signed))); },
            and(rhs) { return new Wrapper(normalize(unwrap(this) & parse(rhs, signed))); },
            or(rhs) { return new Wrapper(normalize(unwrap(this) | parse(rhs, signed))); },
            xor(rhs) { return new Wrapper(normalize(unwrap(this) ^ parse(rhs, signed))); },
            shr(rhs) { return new Wrapper(normalize(unwrap(this) >> BigInt(Number(parse(rhs, signed)) & 63))); },
            shl(rhs) { return new Wrapper(normalize(unwrap(this) << BigInt(Number(parse(rhs, signed)) & 63))); },
            not() { return new Wrapper(normalize(~unwrap(this))); },
            compare(rhs) {
                const lhs = unwrap(this);
                const other = parse(rhs, signed);
                return lhs === other ? 0 : (lhs < other ? -1 : 1);
            },
            toNumber() { return Number(unwrap(this)); },
            toString(radix) { return unwrap(this).toString(requireRadix(radix)); },
            toJSON() { return unwrap(this).toString(10); },
            valueOf() { return Number(unwrap(this)); }
        };
        for (const [methodName, method] of Object.entries(methods)) {
            Object.defineProperty(Wrapper.prototype, methodName, {
                configurable: true,
                writable: true,
                value: method
            });
        }
        Object.defineProperty(Wrapper.prototype, "constructor", {
            configurable: true,
            writable: true,
            value: Wrapper
        });
        return Wrapper;
    }

    Object.defineProperties(globalThis, {
        Int64: { configurable: true, enumerable: true, writable: true, value: define("Int64", true) },
        UInt64: { configurable: true, enumerable: true, writable: true, value: define("UInt64", false) }
    });
})();
