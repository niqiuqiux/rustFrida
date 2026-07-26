(function () {
    "use strict";

    const native = {
        setTimeout: globalThis.__rf_set_timeout,
        setInterval: globalThis.__rf_set_interval,
        clearTimer: globalThis.__rf_clear_timer,
        nextTick: globalThis.__rf_next_tick,
        send: globalThis.__rf_send,
        drainMessages: globalThis.__rf_drain_messages,
        pendingMessageCount: globalThis.__rf_pending_message_count
    };

    function define(name, value) {
        Object.defineProperty(globalThis, name, {
            enumerable: true,
            configurable: true,
            writable: true,
            value: value
        });
    }

    // ------------------------------------------------------------- timers ---

    define("setTimeout", function (func, delay, ...args) {
        if (typeof func !== "function")
            throw new TypeError("setTimeout: callback must be a function");
        return native.setTimeout(function () {
            func.apply(null, args);
        }, delay === undefined ? 0 : delay);
    });

    define("setInterval", function (func, delay, ...args) {
        if (typeof func !== "function")
            throw new TypeError("setInterval: callback must be a function");
        return native.setInterval(function () {
            func.apply(null, args);
        }, delay === undefined ? 0 : delay);
    });

    define("clearTimeout", function (id) { native.clearTimer(id); });
    define("clearInterval", function (id) { native.clearTimer(id); });
    define("setImmediate", function (func, ...args) {
        return globalThis.setTimeout(func, 0, ...args);
    });
    define("clearImmediate", function (id) { native.clearTimer(id); });

    // ------------------------------------------------------------ messages ---

    // recv() callbacks are one-shot, matching upstream: the handler is removed
    // before it runs, so a handler that calls recv() again re-arms cleanly.
    const messageHandlers = new Map();

    function claimHandler(type) {
        if (messageHandlers.has(type))
            return messageHandlers.get(type);
        if (type !== "*" && messageHandlers.has("*"))
            return messageHandlers.get("*");
        return undefined;
    }

    function removeHandler(type) {
        if (messageHandlers.delete(type))
            return;
        messageHandlers.delete("*");
    }

    Object.defineProperty(globalThis, "__rf_dispatch_message", {
        value(json, data) {
            let message;
            try {
                message = JSON.parse(json);
            } catch (error) {
                message = { type: "send", payload: json };
            }
            const type = typeof message.type === "string" ? message.type : "send";
            const handler = claimHandler(type);
            if (handler === undefined)
                return false;
            removeHandler(type);
            handler(message, data === null ? null : data);
            return true;
        }
    });

    function RecvRequest(type) {
        this._type = type;
    }

    // Upstream returns an object whose wait() blocks until the message arrives.
    // Without a blocking scheduler the closest honest behaviour is to drain
    // whatever has already been queued.
    RecvRequest.prototype.wait = function () {
        native.drainMessages();
        return this;
    };

    define("recv", function (type, callback) {
        if (arguments.length === 1) {
            callback = type;
            type = "*";
        }
        if (typeof callback !== "function")
            throw new TypeError("recv: callback must be a function");
        messageHandlers.set(type, callback);
        // A message may already be waiting from before the callback existed.
        native.drainMessages();
        return new RecvRequest(type);
    });

    define("send", function (payload, data) {
        native.send(JSON.stringify({ type: "send", payload: payload }), data === undefined ? null : data);
    });

    // ------------------------------------------------------------- Script ----

    const Script = {};
    Object.defineProperties(Script, {
        runtime: { enumerable: true, value: "QJS" },
        // rustFrida runs one script per runtime, so the id is stable.
        id: { enumerable: true, value: "rustfrida" },
        nextTick: {
            enumerable: true,
            value(callback, ...args) {
                if (typeof callback !== "function")
                    throw new TypeError("Script.nextTick: callback must be a function");
                native.nextTick(function () {
                    callback.apply(globalThis, args);
                });
            }
        },
        // Pinning keeps a script alive against unload in upstream. rustFrida's
        // lifetime is driven by the host session, so these are accepted and
        // recorded rather than silently ignored.
        pin: { enumerable: true, value() { Script._pinned = (Script._pinned || 0) + 1; } },
        unpin: { enumerable: true, value() { Script._pinned = Math.max(0, (Script._pinned || 0) - 1); } },
        bindWeak: {
            enumerable: true,
            value(target, callback) {
                if (typeof callback !== "function")
                    throw new TypeError("Script.bindWeak: callback must be a function");
                const id = Script._nextWeakId++;
                Script._weak.set(id, { target: target, callback: callback });
                return id;
            }
        },
        unbindWeak: {
            enumerable: true,
            value(id) {
                const entry = Script._weak.get(id);
                if (entry === undefined)
                    return;
                Script._weak.delete(id);
                // Upstream invokes the callback when the binding is dropped.
                globalThis.setTimeout(entry.callback, 0);
            }
        },
        _pinned: { writable: true, value: 0 },
        _weak: { value: new Map() },
        _nextWeakId: { writable: true, value: 1 },
        _pendingMessages: { enumerable: true, value() { return native.pendingMessageCount(); } }
    });
    define("Script", Script);

    // --------------------------------------------------------------- Frida ---

    const Frida = {};
    Object.defineProperties(Frida, {
        // The Gum the agent is built against; see frida-gum-sys/FRIDA_VERSION.
        version: { enumerable: true, value: "17.15.5" },
        heapSize: {
            enumerable: true,
            get() { return 0; }
        }
    });
    define("Frida", Frida);

    // ------------------------------------------------- Memory.scan promise ---

    // Upstream's Memory.scan resolves once the scan completes, with onMatch
    // still delivered as it goes. The callback form stays available underneath.
    const nativeScan = Memory.scan;
    Object.defineProperty(Memory, "scan", {
        configurable: true,
        writable: true,
        value(address, size, pattern, callbacks) {
            callbacks = callbacks || {};
            let onSuccess;
            let onFailure;
            const request = new Promise((resolve, reject) => {
                onSuccess = resolve;
                onFailure = reject;
            });
            nativeScan.call(Memory, address, size, pattern, {
                onMatch: callbacks.onMatch,
                onError(reason) {
                    if (typeof callbacks.onError === "function")
                        callbacks.onError(reason);
                    onFailure(new Error(reason));
                },
                onComplete() {
                    if (typeof callbacks.onComplete === "function")
                        callbacks.onComplete();
                    onSuccess();
                }
            });
            return request;
        }
    });

    // ------------------------------------------------------------- hexdump ---

    define("hexdump", function (target, options) {
        options = options || {};
        const length = options.length !== undefined ? options.length : 16 * 16;
        const offset = options.offset !== undefined ? options.offset : 0;
        const header = options.header !== undefined ? options.header : true;
        const ansi = options.ansi !== undefined ? options.ansi : false;

        let bytes;
        let baseAddress;
        if (target instanceof ArrayBuffer) {
            bytes = new Uint8Array(target, offset, Math.min(length, target.byteLength - offset));
            baseAddress = null;
        } else {
            const pointer = target instanceof NativePointer ? target : ptr(target);
            baseAddress = pointer.add(offset);
            bytes = new Uint8Array(baseAddress.readByteArray(length));
        }

        const columns = 16;
        const lines = [];
        if (header) {
            lines.push(
                "        " +
                Array.from({ length: columns }, (_, index) => index.toString(16).padStart(2, "0")).join(" ") +
                "  0123456789ABCDEF"
            );
        }

        const reset = ansi ? "[0m" : "";
        const dim = ansi ? "[2m" : "";
        for (let start = 0; start < bytes.length; start += columns) {
            const slice = bytes.subarray(start, Math.min(start + columns, bytes.length));
            const address = baseAddress === null
                ? start.toString(16).padStart(8, "0")
                : baseAddress.add(start).toString(16).slice(-8).padStart(8, "0");
            const hex = Array.from(slice, byte => byte.toString(16).padStart(2, "0")).join(" ");
            const text = Array.from(slice, byte => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : "."))
                .join("");
            lines.push(dim + address + reset + "  " + hex.padEnd(columns * 3 - 1, " ") + "  " + text);
        }
        return lines.join("\n");
    });
})();
