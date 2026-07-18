function pass(name, value) {
    console.log("[stalker-callout][PASS] " + name + "=" + value);
}

function assertTrue(name, value) {
    if (!value)
        throw new Error(name + ": expected truthy value, got " + value);
    pass(name, value);
}

function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected))
        throw new Error(name + ": expected " + expected + ", got " + actual);
    pass(name, actual);
}

function requireTrue(name, value) {
    if (!value)
        throw new Error(name + ": expected truthy value, got " + value);
}

function requireEqual(name, actual, expected) {
    if (String(actual) !== String(expected))
        throw new Error(name + ": expected " + expected + ", got " + actual);
}

function arraysEqual(left, right) {
    if (left.length !== right.length)
        return false;
    for (var index = 0; index !== left.length; index++) {
        if (left[index] !== right[index])
            return false;
    }
    return true;
}

var target = Module.findExportByName("librfhooktarget.so", "rf_native_add");
assertTrue("native target", target !== null);

var callbacks = new CModule(`
#include <stdint.h>

typedef struct {
    volatile uint32_t hits;
    volatile uint32_t context_ok;
    volatile uint32_t data_ok;
    uint32_t delta;
    volatile uint32_t original_x1;
} CalloutState;

void on_callout(void *cpu_context, void *user_data) {
    CalloutState *state = (CalloutState *) user_data;
    unsigned long *registers;
    state->hits++;
    state->data_ok = (state->delta == 9);
    if (cpu_context == 0)
        return;

    registers = (unsigned long *) cpu_context;
    state->context_ok = (registers[0] != 0);
    state->original_x1 = (uint32_t) registers[4];
    registers[4] = registers[4] + state->delta;
}
`);
pass("CModule compiled", true);

var state = Memory.alloc(32);
state.writeByteArray(new ArrayBuffer(32));
state.add(12).writeU32(9);

var nativeAdd = new NativeFunction(target, "int", ["int", "int"]);
var baseline = nativeAdd(5, 7);
var threadId = Process.getCurrentThreadId();
var transformHits = 0;
var jsCalloutHits = 0;
var callbackError = null;
var savedContext = null;
var inserted = false;

Stalker.follow(threadId, {
    transform(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            transformHits++;
            if (!inserted && instruction.address.equals(target)) {
                inserted = true;
                iterator.putCallout(function (context) {
                    jsCalloutHits++;
                    savedContext = context;
                    try {
                        requireTrue("callout pc", context.pc.equals(target));
                        requireTrue("callout sp", context.sp !== null && typeof context.sp.equals === "function");
                        requireTrue("callout nzcv", Number.isInteger(context.nzcv));

                        var gprNames = ["pc", "sp"];
                        for (var index = 0; index !== 29; index++)
                            gprNames.push("x" + index);
                        gprNames.push("fp", "lr");
                        for (var gprIndex = 0; gprIndex !== gprNames.length; gprIndex++) {
                            var name = gprNames[gprIndex];
                            var value = context[name];
                            requireTrue(name + " readable", value !== null && typeof value.equals === "function");
                            context[name] = value;
                            requireTrue(name + " writable", context[name].equals(value));
                        }

                        var flags = context.nzcv;
                        context.nzcv = flags;
                        requireEqual("nzcv writable", context.nzcv, flags);

                        for (var vectorIndex = 0; vectorIndex !== 32; vectorIndex++) {
                            var vectorName = "q" + vectorIndex;
                            var original = context[vectorName];
                            requireTrue(vectorName + " ArrayBuffer", original instanceof ArrayBuffer);
                            requireEqual(vectorName + " size", original.byteLength, 16);
                            var originalBytes = new Uint8Array(original);
                            var replacement = new Uint8Array(originalBytes);
                            context[vectorName] = replacement;
                            requireTrue(
                                vectorName + " writable",
                                arraysEqual(new Uint8Array(context[vectorName]), replacement)
                            );
                        }

                        var snapshot = context.toJSON();
                        requireTrue("context snapshot pc", snapshot.pc.equals(target));
                        requireEqual("context snapshot q31", snapshot.q31.byteLength, 16);
                        context.x0 = ptr(23);
                    } catch (error) {
                        callbackError = String(error);
                    }
                });
                iterator.putCallout(callbacks.on_callout, state);
            }
            iterator.keep();
        }
    },
    events: {}
});

var modifiedResult = nativeAdd(5, 7);
Stalker.unfollow(threadId);
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();

assertTrue("transform visited target", inserted && transformHits > 0);
assertEqual("JavaScript callout hits", jsCalloutHits, 1);
assertEqual("JavaScript callout error", callbackError, null);
assertEqual("CModule callout hits", state.readU32(), 1);
assertEqual("CModule context", state.add(4).readU32(), 1);
assertEqual("CModule data", state.add(8).readU32(), 1);
assertEqual("CModule original x1", state.add(16).readU32(), 7);
assertEqual("register modifications", modifiedResult, 23 + 7 + 9 + 100);

var expiredContextRejected = false;
try {
    savedContext.x0;
} catch (error) {
    expiredContextRejected = /outside a Stalker callout callback/.test(String(error));
}
assertTrue("CpuContext expires after callback", expiredContextRejected);

assertEqual("target restored", nativeAdd(5, 7), baseline);
console.log("[stalker-callout][READY] JavaScript/CModule callouts and ARM64 CpuContext verified");
