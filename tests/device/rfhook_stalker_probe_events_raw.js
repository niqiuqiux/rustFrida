function pass(name, value) {
    console.log("[stalker-probe-events-raw][PASS] " + name + "=" + value);
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
var firstHits = 0;
var secondHits = 0;
var batchCount = 0;
var eventCount = 0;

var firstId = Stalker.addCallProbe(target, function (args) {
    firstHits++;
    args[0] = args[0].add(10);
});
var secondId = Stalker.addCallProbe(target, function (args) {
    secondHits++;
    args[1] = args[1].add(20);
});

Stalker.queueDrainInterval = 50;
Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: true },
    onReceive(events) {
        batchCount++;
        eventCount += Stalker.parse(events).length;
    }
});

assertEqual("both probes", nativeAdd(4, 5), baseline + 30);
assertEqual("first probe hit", firstHits, 1);
assertEqual("second probe hit", secondHits, 1);
assertEqual("remove first probe", Stalker.removeCallProbe(firstId), undefined);
assertEqual("remaining probe", nativeAdd(4, 5), baseline + 20);
assertEqual("remaining probe hit", secondHits, 2);
assertEqual("remove last probe", Stalker.removeCallProbe(secondId), undefined);
assertEqual("target restored", nativeAdd(4, 5), baseline);

var replacementHits = 0;
var replacementId = Stalker.addCallProbe(target, function (args) {
    replacementHits++;
    args[0] = args[0].add(40);
});
assertEqual("replacement probe", nativeAdd(4, 5), baseline + 40);
assertEqual("replacement probe hit", replacementHits, 1);
assertEqual("remove replacement probe", Stalker.removeCallProbe(replacementId), undefined);
assertEqual("target restored again", nativeAdd(4, 5), baseline);

Stalker.unfollow(Process.getCurrentThreadId());
Stalker.flush();
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();

assertTrue("event batches delivered", batchCount > 0);
assertTrue("events delivered", eventCount > 0);
console.log("[stalker-probe-events-raw][READY] event sink and probe invalidation verified");
