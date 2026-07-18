function pass(name, value) {
    console.log("[stalker-transform][PASS] " + name + "=" + value);
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

var target = Module.findExportByName("librfhooktarget.so", "rf_native_add");
assertTrue("native target", target !== null);

var nativeAdd = new NativeFunction(target, "int", ["int", "int"]);
var baseline = nativeAdd(9, 4);
var secondBaseline = nativeAdd(17, 6);
var threadId = Process.getCurrentThreadId();
var transformCalls = 0;
var instructionCount = 0;
var retainedIterator = null;
var firstInstruction = null;
var memoryAccess = null;

var invalidTransformRejected = false;
try {
    Stalker.follow(threadId, { transform: 7 });
} catch (error) {
    invalidTransformRejected = error instanceof TypeError;
}
assertTrue("invalid transform rejected", invalidTransformRejected);

Stalker.follow(threadId, {
    transform(iterator) {
        transformCalls++;
        if (retainedIterator === null) {
            retainedIterator = iterator;
            memoryAccess = iterator.memoryAccess;
        }

        var instruction;
        while ((instruction = iterator.next()) !== null) {
            instructionCount++;
            if (firstInstruction === null) {
                firstInstruction = {
                    id: instruction.id,
                    address: instruction.address,
                    next: instruction.next,
                    size: instruction.size,
                    mnemonic: instruction.mnemonic,
                    opStr: instruction.opStr,
                    text: instruction.toString(),
                    bytes: instruction.bytes
                };
            }
            iterator.keep();
        }
    },
    events: { call: true }
});

assertEqual("transformed native call", nativeAdd(9, 4), baseline);
assertEqual("second transformed native call", nativeAdd(17, 6), secondBaseline);

Stalker.unfollow(threadId);
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();

assertTrue("transform callback invoked", transformCalls > 0);
assertTrue("instructions iterated", instructionCount > 0);
assertTrue("memoryAccess value", memoryAccess === "open" || memoryAccess === "exclusive");
assertTrue("instruction id", Number.isInteger(firstInstruction.id) && firstInstruction.id >= 0);
assertTrue("instruction address", firstInstruction.address !== null && typeof firstInstruction.address.equals === "function");
assertTrue("instruction next", firstInstruction.next !== null && typeof firstInstruction.next.equals === "function");
assertTrue("instruction size", Number.isInteger(firstInstruction.size) && firstInstruction.size > 0);
assertTrue("instruction mnemonic", typeof firstInstruction.mnemonic === "string" && firstInstruction.mnemonic.length > 0);
assertTrue("instruction opStr", typeof firstInstruction.opStr === "string");
assertTrue("instruction text", typeof firstInstruction.text === "string" && firstInstruction.text.length > 0);
assertTrue("instruction bytes", firstInstruction.bytes instanceof ArrayBuffer && firstInstruction.bytes.byteLength > 0);
assertEqual("instruction next address", firstInstruction.next, firstInstruction.address.add(firstInstruction.size));

var expiredIteratorRejected = false;
try {
    retainedIterator.next();
} catch (error) {
    expiredIteratorRejected = /outside a Stalker transform callback/.test(String(error));
}
assertTrue("iterator expires after callback", expiredIteratorRejected);

assertEqual("target remains intact", nativeAdd(9, 4), baseline);
console.log("[stalker-transform][READY] JavaScript transform verified");
