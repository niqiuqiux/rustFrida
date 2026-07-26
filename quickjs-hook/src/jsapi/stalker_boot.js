(function () {
    "use strict";

    const native = {
        isSupported: globalThis.__rf_stalker_is_supported,
        follow: globalThis.__rf_stalker_follow,
        drainDue: globalThis.__rf_stalker_drain_due,
        unfollow: globalThis.__rf_stalker_unfollow,
        flush: globalThis.__rf_stalker_flush,
        garbageCollect: globalThis.__rf_stalker_garbage_collect,
        exclude: globalThis.__rf_stalker_exclude,
        invalidate: globalThis.__rf_stalker_invalidate,
        addCallProbe: globalThis.__rf_stalker_add_call_probe,
        removeCallProbe: globalThis.__rf_stalker_remove_call_probe,
        getProbeArgument: globalThis.__rf_stalker_get_probe_argument,
        setProbeArgument: globalThis.__rf_stalker_set_probe_argument,
        transformNext: globalThis.__rf_stalker_transform_next,
        transformKeep: globalThis.__rf_stalker_transform_keep,
        transformKeepAll: globalThis.__rf_stalker_transform_keep_all,
        transformGetInstructionField: globalThis.__rf_stalker_transform_get_instruction_field,
        transformGetMemoryAccess: globalThis.__rf_stalker_transform_get_memory_access,
        transformPutCallout: globalThis.__rf_stalker_transform_put_callout,
        transformPutChainingReturn: globalThis.__rf_stalker_transform_put_chaining_return,
        calloutGetRegister: globalThis.__rf_stalker_callout_get_register,
        calloutSetRegister: globalThis.__rf_stalker_callout_set_register,
        takeRetiredCallouts: globalThis.__rf_stalker_take_retired_callouts,
        statistics: globalThis.__rf_stalker_statistics,
        getTrustThreshold: globalThis.__rf_stalker_get_trust_threshold,
        setTrustThreshold: globalThis.__rf_stalker_set_trust_threshold,
        writerSpec: globalThis.__rf_stalker_writer_spec,
        writerInvoke: globalThis.__rf_stalker_writer_invoke,
        relocatorCreate: globalThis.__rf_stalker_relocator_create,
        relocatorDestroy: globalThis.__rf_stalker_relocator_destroy,
        relocatorInvoke: globalThis.__rf_stalker_relocator_invoke
    };

    const eventTypes = Object.freeze({
        call: 1,
        ret: 2,
        exec: 4,
        block: 8,
        compile: 16
    });
    const listeners = new Map();
    const transforms = new Map();
    const callProbes = new Map();
    const nativeCallProbeRoots = new Map();
    const callouts = new Map();
    const nativeCalloutRoots = new Map();
    const retiredListenerRoots = [];
    const retiredNativeCallProbeRoots = [];
    let nextCallProbeId = 1;
    let nextCalloutId = 1;
    let queueCapacity = 16384;
    let queueDrainInterval = 250;

    function currentThreadId() {
        return Process.getCurrentThreadId();
    }

    function requireUint32(value, name) {
        if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
            throw new TypeError(name + " must be an unsigned 32-bit integer");
        return value;
    }

    function requireArgumentIndex(property) {
        if (typeof property !== "string" || !/^(0|[1-9][0-9]*)$/.test(property))
            throw new RangeError("invalid array index");
        return requireUint32(Number(property), "argument index");
    }

    function isNullAddress(value) {
        if (typeof value === "number" || typeof value === "bigint")
            return value === 0 || value === 0n;
        return value !== null && typeof value.isNull === "function" && value.isNull();
    }

    function allocateCallProbeId() {
        for (;;) {
            const id = nextCallProbeId;
            nextCallProbeId = id === 0xffffffff ? 1 : id + 1;
            if (!callProbes.has(id) && !nativeCallProbeRoots.has(id))
                return id;
        }
    }

    function allocateCalloutId() {
        for (;;) {
            const id = nextCalloutId;
            nextCalloutId = id === 0xffffffff ? 1 : id + 1;
            if (!callouts.has(id) && !nativeCalloutRoots.has(id))
                return id;
        }
    }

    function pruneCallouts() {
        for (const id of native.takeRetiredCallouts()) {
            callouts.delete(id);
            nativeCalloutRoots.delete(id);
        }
    }

    const probeArgs = new Proxy(Object.create(null), {
        get(_target, property) {
            if (property === "toJSON")
                return "probe-args";
            return native.getProbeArgument(requireArgumentIndex(property));
        },
        set(_target, property, value) {
            native.setProbeArgument(requireArgumentIndex(property), value);
            return true;
        }
    });

    const calloutContext = Object.create(null);
    const calloutContextFields = [];

    function defineCalloutRegister(name, field) {
        calloutContextFields.push(name);
        Object.defineProperty(calloutContext, name, {
            enumerable: true,
            get() { return native.calloutGetRegister(field); },
            set(value) { native.calloutSetRegister(field, value); }
        });
    }

    defineCalloutRegister("pc", 32);
    defineCalloutRegister("sp", 31);
    defineCalloutRegister("nzcv", 33);
    for (let index = 0; index !== 29; index++)
        defineCalloutRegister("x" + index, index);
    defineCalloutRegister("fp", 29);
    defineCalloutRegister("lr", 30);
    for (let index = 0; index !== 32; index++)
        defineCalloutRegister("q" + index, 64 + index);
    Object.defineProperty(calloutContext, "toJSON", {
        value() {
            const snapshot = Object.create(null);
            for (const name of calloutContextFields)
                snapshot[name] = this[name];
            return snapshot;
        }
    });

    const instructionPrototype = Object.create(null);
    Object.defineProperty(instructionPrototype, "toString", {
        value() {
            return this.opStr.length === 0 ? this.mnemonic : this.mnemonic + " " + this.opStr;
        }
    });

    // ARM64 code writer surface. The opcode table, argument specs and enum
    // values all come from native so the JavaScript side never hardcodes
    // Capstone or Gum numbering.
    const writerSpec = native.writerSpec();
    const writerRegisters = writerSpec.registers;
    const writerConditions = writerSpec.conditions;
    const writerIndexModes = writerSpec.indexModes;

    // Gum treats a label id as an opaque key and never dereferences it, so the
    // facade maps each label name to a unique integer. Ids are never reused, so
    // a name reappearing in a later transform callback cannot bind to a label
    // Gum already resolved.
    let nextLabelId = 0x10000;
    const transformLabels = new Map();

    function labelIdFor(value) {
        if (typeof value === "number") {
            if (!Number.isInteger(value) || value <= 0)
                throw new TypeError("label id must be a positive integer");
            return value;
        }
        if (typeof value !== "string")
            throw new TypeError("label must be a string");
        let id = transformLabels.get(value);
        if (id === undefined) {
            id = nextLabelId++;
            transformLabels.set(value, id);
        }
        return id;
    }

    function registerIdFor(value, methodName) {
        if (typeof value === "string") {
            const id = writerRegisters[value];
            if (id === undefined)
                throw new TypeError(methodName + "(): unknown register name '" + value + "'");
            return id;
        }
        if (typeof value === "number" && Number.isInteger(value) && value >= 0)
            return value;
        throw new TypeError(methodName + "(): expected a register name");
    }

    function enumIdFor(table, value, kind, methodName) {
        if (typeof value === "string") {
            const id = table[value];
            if (id === undefined)
                throw new TypeError(methodName + "(): unknown " + kind + " '" + value + "'");
            return id;
        }
        if (typeof value === "number" && Number.isInteger(value) && value >= 0)
            return value;
        throw new TypeError(methodName + "(): expected a " + kind);
    }

    // Accepts plain numbers, BigInt, and the NativePointer/Int64/UInt64 wrappers
    // whose toString() yields a value BigInt can parse.
    function integerFor(value, methodName) {
        const kind = typeof value;
        if (kind === "number" || kind === "bigint")
            return value;
        if (kind === "string")
            return BigInt(value);
        if (value !== null && kind === "object" && typeof value.toString === "function")
            return BigInt(value.toString());
        throw new TypeError(methodName + "(): expected an integer");
    }

    function callArgumentsFor(value, methodName) {
        if (!Array.isArray(value))
            throw new TypeError(methodName + "(): expected an array of arguments");
        const flattened = [value.length];
        for (const argument of value) {
            if (typeof argument === "string") {
                flattened.push(0, registerIdFor(argument, methodName));
            } else {
                flattened.push(1, integerFor(argument, methodName));
            }
        }
        return flattened;
    }

    function convertWriterArguments(spec, methodName, args) {
        const converted = new Array(spec.length);
        for (let index = 0; index !== spec.length; index++) {
            const value = args[index];
            switch (spec[index]) {
                case "r":
                    converted[index] = registerIdFor(value, methodName);
                    break;
                case "c":
                    converted[index] = enumIdFor(writerConditions, value, "condition code", methodName);
                    break;
                case "m":
                    converted[index] = enumIdFor(writerIndexModes, value, "index mode", methodName);
                    break;
                case "l":
                    converted[index] = labelIdFor(value);
                    break;
                case "u":
                case "s":
                    converted[index] = integerFor(value, methodName);
                    break;
                case "A":
                    converted[index] = callArgumentsFor(value, methodName);
                    break;
                default:
                    // "a" (address) and "b" (bytes) are forwarded untouched.
                    converted[index] = value;
                    break;
            }
        }
        return converted;
    }

    function defineWriterMembers(target, state, methods, invoke) {
        for (const method of methods) {
            const { name, opcode, argSpec } = method;
            if (method.kind === "property") {
                Object.defineProperty(target, name, {
                    enumerable: true,
                    get() { return invoke(state, opcode, []); }
                });
                continue;
            }
            Object.defineProperty(target, name, {
                enumerable: true,
                value(...args) {
                    if (args.length < argSpec.length)
                        throw new TypeError(name + "() expects " + argSpec.length + " argument(s)");
                    return invoke(state, opcode, convertWriterArguments(argSpec, name, args));
                }
            });
        }
    }

    function invokeIteratorWriter(state, opcode, args) {
        return native.writerInvoke(state.token, opcode, ...args);
    }

    // Lets `new Arm64Relocator(input, iterator)` find the transform token that
    // owns the output writer without exposing the token to scripts.
    const relocatorStates = new WeakMap();

    function createTransformEntry(callback) {
        const state = { token: 0 };
        const instruction = Object.create(instructionPrototype);
        Object.defineProperties(instruction, {
            id: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 0); } },
            address: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 1); } },
            next: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 2); } },
            size: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 3); } },
            mnemonic: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 4); } },
            opStr: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 5); } },
            bytes: { enumerable: true, get() { return native.transformGetInstructionField(state.token, 6); } }
        });

        const iterator = Object.create(null);
        Object.defineProperties(iterator, {
            memoryAccess: {
                enumerable: true,
                get() {
                    const value = native.transformGetMemoryAccess(state.token);
                    if (value === 0)
                        return "open";
                    if (value === 1)
                        return "exclusive";
                    throw new Error("invalid Stalker memory access mode: " + value);
                }
            },
            next: {
                enumerable: true,
                value() {
                    return native.transformNext(state.token) ? instruction : null;
                }
            },
            keep: {
                enumerable: true,
                value() { native.transformKeep(state.token); }
            },
            putCallout: {
                enumerable: true,
                value(callback, data) {
                    const isJavaScriptCallback = typeof callback === "function";
                    if (!isJavaScriptCallback && (callback === null || callback === undefined))
                        throw new TypeError("callback must be a function or pointer");
                    if (!isJavaScriptCallback && isNullAddress(callback))
                        throw new TypeError("callback must not be NULL");
                    if (data === undefined)
                        data = NULL;

                    const id = allocateCalloutId();
                    if (isJavaScriptCallback)
                        callouts.set(id, callback);
                    else
                        nativeCalloutRoots.set(id, { callback, data });
                    try {
                        native.transformPutCallout(
                            state.token,
                            id,
                            isJavaScriptCallback ? NULL : callback,
                            isJavaScriptCallback ? NULL : data
                        );
                    } catch (error) {
                        callouts.delete(id);
                        nativeCalloutRoots.delete(id);
                        throw error;
                    }
                }
            },
            putChainingReturn: {
                enumerable: true,
                value() { native.transformPutChainingReturn(state.token); }
            }
        });
        // Upstream models the transform iterator as a subclass of Arm64Writer,
        // so the writer members live directly on the iterator.
        defineWriterMembers(iterator, state, writerSpec.methods, invokeIteratorWriter);
        Object.defineProperty(iterator, "dispose", {
            enumerable: true,
            // The Stalker output writer is owned by Gum and retired when the
            // transform callback returns; disposing it from a script would break
            // code generation for the rest of the block.
            value() {}
        });
        relocatorStates.set(iterator, state);
        return { callback, state, iterator };
    }

    function createRelocator(inputCode, output) {
        if (output === null || output === undefined)
            throw new TypeError("Arm64Relocator requires an output writer");
        const state = relocatorStates.get(output);
        if (state === undefined)
            throw new TypeError("Arm64Relocator output must be the current Stalker transform iterator");
        if (state.token === 0)
            throw new Error("invalid operation outside a Stalker transform callback");

        const handle = native.relocatorCreate(state.token, inputCode);
        const relocator = Object.create(null);
        const relocatorState = { token: state.token, handle, disposed: false };
        defineWriterMembers(relocator, relocatorState, writerSpec.relocatorMethods, invokeRelocator);
        Object.defineProperty(relocator, "dispose", {
            enumerable: true,
            value() {
                if (relocatorState.disposed)
                    return;
                relocatorState.disposed = true;
                native.relocatorDestroy(relocatorState.token, relocatorState.handle);
            }
        });
        return relocator;
    }

    function invokeRelocator(state, opcode, args) {
        if (state.disposed)
            throw new Error("Arm64Relocator has already been disposed");
        return native.relocatorInvoke(state.token, state.handle, opcode, ...args);
    }

    function pointerAt(view, offset, stringify) {
        const low = BigInt(view.getUint32(offset, true));
        const high = BigInt(view.getUint32(offset + 4, true));
        const value = (high << 32n) | low;
        const text = "0x" + value.toString(16);
        return stringify ? text : ptr(text);
    }

    function parse(events, options) {
        if (!(events instanceof ArrayBuffer))
            throw new TypeError("events must be an ArrayBuffer");
        if ((events.byteLength % 32) !== 0)
            throw new Error("invalid buffer shape");

        if (options === undefined)
            options = {};
        if (options === null || typeof options !== "object")
            throw new TypeError("options must be an object");
        const annotate = options.annotate === undefined ? true : Boolean(options.annotate);
        const stringify = options.stringify === undefined ? false : Boolean(options.stringify);
        const view = new DataView(events);
        const rows = [];

        for (let offset = 0; offset < events.byteLength; offset += 32) {
            const type = view.getUint32(offset, true);
            const row = [];
            switch (type) {
                case 1:
                    if (annotate) row.push("call");
                    row.push(pointerAt(view, offset + 8, stringify));
                    row.push(pointerAt(view, offset + 16, stringify));
                    row.push(view.getInt32(offset + 24, true));
                    break;
                case 2:
                    if (annotate) row.push("ret");
                    row.push(pointerAt(view, offset + 8, stringify));
                    row.push(pointerAt(view, offset + 16, stringify));
                    row.push(view.getInt32(offset + 24, true));
                    break;
                case 4:
                    if (annotate) row.push("exec");
                    row.push(pointerAt(view, offset + 8, stringify));
                    break;
                case 8:
                    if (annotate) row.push("block");
                    row.push(pointerAt(view, offset + 8, stringify));
                    row.push(pointerAt(view, offset + 16, stringify));
                    break;
                case 16:
                    if (annotate) row.push("compile");
                    row.push(pointerAt(view, offset + 8, stringify));
                    row.push(pointerAt(view, offset + 16, stringify));
                    break;
                default:
                    throw new Error("invalid event type");
            }
            rows.push(row);
        }
        return rows;
    }

    function dispatch(batches) {
        for (const batch of batches) {
            const listener = listeners.get(batch.threadId);
            if (listener === undefined)
                continue;

            if (listener.onReceive !== null)
                listener.onReceive(batch.data);

            if (listener.onCallSummary !== null) {
                const summary = Object.create(null);
                for (const row of parse(batch.data, { annotate: true, stringify: true })) {
                    if (row[0] !== "call")
                        continue;
                    const target = row[2];
                    summary[target] = (summary[target] || 0) + 1;
                }
                listener.onCallSummary(summary);
            }
        }
    }

    Object.defineProperty(globalThis, "__rf_stalker_dispatch_due", {
        value() {
            dispatch(native.drainDue());
            pruneCallouts();
        }
    });

    Object.defineProperty(globalThis, "__rf_stalker_dispatch_call_probe", {
        value(id) {
            const callback = callProbes.get(id);
            if (typeof callback === "function")
                callback(probeArgs);
        }
    });

    Object.defineProperty(globalThis, "__rf_stalker_dispatch_transform", {
        value(threadId, token) {
            pruneCallouts();
            const entry = transforms.get(threadId);
            if (entry === undefined) {
                native.transformKeepAll(token);
                return;
            }
            entry.state.token = token;
            // Label names are scoped to a single callback: the writer they were
            // resolved against stops being valid once it returns.
            transformLabels.clear();
            try {
                entry.callback(entry.iterator);
            } catch (error) {
                transforms.delete(threadId);
                throw error;
            } finally {
                entry.state.token = 0;
                transformLabels.clear();
            }
        }
    });

    Object.defineProperty(globalThis, "__rf_stalker_dispatch_callout", {
        value(id) {
            pruneCallouts();
            const callback = callouts.get(id);
            if (typeof callback === "function")
                callback(calloutContext);
        }
    });

    const Stalker = {};
    Object.defineProperties(Stalker, {
        supported: {
            enumerable: true,
            get() { return native.isSupported(); }
        },
        trustThreshold: {
            enumerable: true,
            get() { return native.getTrustThreshold(); },
            set(value) {
                if (!Number.isInteger(value) || value < -0x80000000 || value > 0x7fffffff)
                    throw new TypeError("trustThreshold must be a signed 32-bit integer");
                native.setTrustThreshold(value);
            }
        },
        queueCapacity: {
            enumerable: true,
            get() { return queueCapacity; },
            set(value) { queueCapacity = requireUint32(value, "queueCapacity"); }
        },
        queueDrainInterval: {
            enumerable: true,
            get() { return queueDrainInterval; },
            set(value) { queueDrainInterval = requireUint32(value, "queueDrainInterval"); }
        },
        exclude: {
            enumerable: true,
            value(range) {
                if (range === null || typeof range !== "object" || range.base === undefined || range.size === undefined)
                    throw new TypeError("range must contain base and size");
                native.exclude(range.base, range.size);
            }
        },
        follow: {
            enumerable: true,
            value(first, second) {
                let threadId = first;
                let options = second;
                if (typeof first === "object") {
                    threadId = undefined;
                    options = first;
                }
                if (threadId === undefined)
                    threadId = currentThreadId();
                if (!Number.isInteger(threadId) || threadId <= 0)
                    throw new TypeError("threadId must be a positive integer");
                if (options === undefined)
                    options = {};
                if (options === null || typeof options !== "object")
                    throw new TypeError("options must be an object");

                const transform = options.transform === undefined ? null : options.transform;
                const events = options.events === undefined ? {} : options.events;
                const onReceive = options.onReceive === undefined ? null : options.onReceive;
                const onCallSummary = options.onCallSummary === undefined ? null : options.onCallSummary;
                const onEvent = options.onEvent === undefined ? NULL : options.onEvent;
                const data = options.data === undefined ? NULL : options.data;
                if (transform !== null && typeof transform !== "function")
                    throw new TypeError("transform must be a function");
                if (events === null || typeof events !== "object")
                    throw new TypeError("events must be an object");
                if (onReceive !== null && typeof onReceive !== "function")
                    throw new TypeError("onReceive must be a function");
                if (onCallSummary !== null && typeof onCallSummary !== "function")
                    throw new TypeError("onCallSummary must be a function");
                if (!data.isNull() && (onReceive !== null || onCallSummary !== null))
                    throw new Error("onEvent precludes passing onReceive/onCallSummary");

                let eventMask = 0;
                for (const name of Object.keys(events)) {
                    if (!Object.prototype.hasOwnProperty.call(eventTypes, name))
                        throw new Error("unknown event type: " + name);
                    if (typeof events[name] !== "boolean")
                        throw new TypeError("desired events must be specified as boolean values");
                    if (events[name])
                        eventMask |= eventTypes[name];
                }

                const previousTransform = transforms.get(threadId);
                const hadPreviousTransform = transforms.has(threadId);
                if (transform !== null)
                    transforms.set(threadId, createTransformEntry(transform));
                else
                    transforms.delete(threadId);
                try {
                    native.follow(
                        threadId,
                        eventMask,
                        queueCapacity,
                        queueDrainInterval,
                        transform === null ? 0 : 1,
                        onEvent,
                        data
                    );
                } catch (error) {
                    if (hadPreviousTransform)
                        transforms.set(threadId, previousTransform);
                    else
                        transforms.delete(threadId);
                    throw error;
                }
                listeners.set(threadId, { onReceive, onCallSummary, onEvent, data });
            }
        },
        unfollow: {
            enumerable: true,
            value(threadId) {
                if (threadId === undefined)
                    threadId = currentThreadId();
                if (!Number.isInteger(threadId) || threadId <= 0)
                    throw new TypeError("threadId must be a positive integer");
                const batches = native.unfollow(threadId);
                dispatch(batches);
                pruneCallouts();
                const listener = listeners.get(threadId);
                if (listener !== undefined)
                    retiredListenerRoots.push(listener);
                listeners.delete(threadId);
                transforms.delete(threadId);
            }
        },
        flush: {
            enumerable: true,
            value() {
                dispatch(native.flush());
                pruneCallouts();
            }
        },
        garbageCollect: {
            enumerable: true,
            value() {
                const result = native.garbageCollect();
                dispatch(result.batches);
                pruneCallouts();
                if (!result.pending) {
                    retiredListenerRoots.length = 0;
                    retiredNativeCallProbeRoots.length = 0;
                }
            }
        },
        invalidate: {
            enumerable: true,
            value(first, second) {
                if (second === undefined)
                    native.invalidate(first);
                else
                    native.invalidate(first, second);
            }
        },
        addCallProbe: {
            enumerable: true,
            value(target, callback, data) {
                const isJavaScriptCallback = typeof callback === "function";
                if (!isJavaScriptCallback && (callback === null || callback === undefined))
                    throw new TypeError("callback must be a function or pointer");
                if (!isJavaScriptCallback && isNullAddress(callback))
                    throw new TypeError("callback must not be NULL");
                if (data === undefined)
                    data = NULL;
                const id = allocateCallProbeId();
                if (isJavaScriptCallback)
                    callProbes.set(id, callback);
                else
                    nativeCallProbeRoots.set(id, { callback, data });
                try {
                    native.addCallProbe(id, target, isJavaScriptCallback ? NULL : callback, isJavaScriptCallback ? NULL : data);
                } catch (error) {
                    callProbes.delete(id);
                    nativeCallProbeRoots.delete(id);
                    throw error;
                }
                return id;
            }
        },
        removeCallProbe: {
            enumerable: true,
            value(id) {
                requireUint32(id, "probeId");
                native.removeCallProbe(id);
                const nativeRoot = nativeCallProbeRoots.get(id);
                if (nativeRoot !== undefined)
                    retiredNativeCallProbeRoots.push(nativeRoot);
                callProbes.delete(id);
                nativeCallProbeRoots.delete(id);
            }
        },
        parse: {
            enumerable: true,
            value: parse
        },
        // rustFrida extension: makes the queue-full path and the retirement
        // queues observable instead of silently dropping events.
        statistics: {
            enumerable: true,
            value() {
                const snapshot = native.statistics();
                // statistics() consumes the callout retirement queue, so release
                // the JS roots here rather than waiting for the next prune.
                for (const id of snapshot.retiredCalloutIds) {
                    callouts.delete(id);
                    nativeCalloutRoots.delete(id);
                }
                delete snapshot.retiredCalloutIds;
                snapshot.liveCallouts = callouts.size + nativeCalloutRoots.size;
                snapshot.liveCallProbes = callProbes.size + nativeCallProbeRoots.size;
                return snapshot;
            }
        }
    });

    globalThis.Stalker = Stalker;

    function Arm64Relocator(inputCode, output) {
        if (!new.target)
            throw new TypeError("use `new Arm64Relocator()` to create a new instance");
        return createRelocator(inputCode, output);
    }
    globalThis.Arm64Relocator = Arm64Relocator;
})();
