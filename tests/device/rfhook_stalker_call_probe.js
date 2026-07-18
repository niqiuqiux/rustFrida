function pass(name, value) {
    console.log("[stalker-probe][PASS] " + name + "=" + value);
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
var baseline = nativeAdd(4, 5);
var threadId = Process.getCurrentThreadId();
var firstHits = 0;
var secondHits = 0;
var observedArgs = [];
var retainedArgs = null;
var nestedGetPid = new NativeFunction(Module.findExportByName("libc.so", "getpid"), "int", []);
var nestedPid = 0;

var firstId = Stalker.addCallProbe(target, function (args) {
    firstHits++;
    nestedPid = nestedGetPid();
    retainedArgs = args;
    observedArgs.push("first:" + args[0].toInt32() + "," + args[1].toInt32());
    args[0] = args[0].add(10);
});
var secondId = Stalker.addCallProbe(target, function (args) {
    secondHits++;
    observedArgs.push("second:" + args[0].toInt32() + "," + args[1].toInt32());
    args[1] = args[1].add(20);
});
assertTrue("unique probe ids", firstId > 0 && secondId > 0 && firstId !== secondId);

Stalker.follow(threadId, { events: {} });
assertEqual("chained argument update", nativeAdd(4, 5), baseline + 30);
assertEqual("probe callback order", observedArgs.join("|"), "first:4,5|second:14,5");
assertEqual("first probe hit", firstHits, 1);
assertEqual("second probe hit", secondHits, 1);
assertTrue("nested NativeFunction remains inside outer activation", nestedPid > 0);

var retainedArgsRejected = false;
try {
    retainedArgs[0];
} catch (error) {
    retainedArgsRejected = true;
}
assertTrue("probe args expire after callback", retainedArgsRejected);

assertEqual("remove first probe", Stalker.removeCallProbe(firstId), undefined);
observedArgs.length = 0;
assertEqual("remaining probe argument update", nativeAdd(4, 5), baseline + 20);
assertEqual("remaining probe args", observedArgs.join("|"), "second:4,5");
assertEqual("removed probe stays detached", firstHits, 1);
assertEqual("remaining probe hit", secondHits, 2);

assertEqual("remove second probe", Stalker.removeCallProbe(secondId), undefined);
assertEqual("target restored", nativeAdd(4, 5), baseline);
assertEqual("idempotent removal", Stalker.removeCallProbe(firstId), undefined);

var selfRemovingHits = 0;
var selfRemovingId = Stalker.addCallProbe(target, function (args) {
    selfRemovingHits++;
    Stalker.flush();
    Stalker.removeCallProbe(selfRemovingId);
    args[0] = args[0].add(40);
});
assertEqual("reentrant flush and self-removal", nativeAdd(4, 5), baseline + 40);
assertEqual("self-removing probe first hit", selfRemovingHits, 1);
assertEqual("self-removing probe detached", nativeAdd(4, 5), baseline);
assertEqual("self-removing probe hit count", selfRemovingHits, 1);
assertEqual("self-removing idempotent removal", Stalker.removeCallProbe(selfRemovingId), undefined);

Stalker.unfollow(threadId);
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();

console.log("[stalker-probe][READY] addCallProbe/removeCallProbe verified");
