function assertTrue(name, value) {
    if (!value)
        throw new Error(name + ": expected truthy value, got " + value);
    console.log("[stalker-callout-minimal][PASS] " + name + "=" + value);
}

function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected))
        throw new Error(name + ": expected " + expected + ", got " + actual);
    console.log("[stalker-callout-minimal][PASS] " + name + "=" + actual);
}

var target = Module.findExportByName("librfhooktarget.so", "rf_native_add");
assertTrue("native target", target !== null);

var nativeAdd = new NativeFunction(target, "int", ["int", "int"]);
var baseline = nativeAdd(5, 7);
var threadId = Process.getCurrentThreadId();
var inserted = false;
var calloutHits = 0;
var seenPc = null;
var seenX0 = null;

console.log("[stalker-callout-minimal][STAGE] before follow");
Stalker.follow(threadId, {
    transform(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (!inserted && instruction.address.equals(target)) {
                inserted = true;
                iterator.putCallout(function (context) {
                    calloutHits++;
                    seenPc = context.pc;
                    seenX0 = context.x0;
                    context.x0 = ptr(23);
                });
            }
            iterator.keep();
        }
    },
    events: {}
});
console.log("[stalker-callout-minimal][STAGE] after follow");

var modifiedResult = nativeAdd(5, 7);
console.log("[stalker-callout-minimal][STAGE] after target call");
Stalker.unfollow(threadId);
console.log("[stalker-callout-minimal][STAGE] after unfollow");
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();
console.log("[stalker-callout-minimal][STAGE] after garbage collection");

assertTrue("callout inserted", inserted);
assertEqual("callout hits", calloutHits, 1);
assertEqual("callout pc", seenPc, target);
assertEqual("callout x0", seenX0, ptr(5));
assertEqual("modified result", modifiedResult, 23 + 7 + 100);
assertEqual("target restored", nativeAdd(5, 7), baseline);
console.log("[stalker-callout-minimal][READY] minimal JavaScript callout verified");
