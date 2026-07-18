function pass(name, value) {
    console.log("[stalker-zero][PASS] " + name + "=" + value);
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

var nativeTarget = Module.findExportByName("librfhooktarget.so", "rf_native_add");
var usleepTarget = Module.findExportByName("libc.so", "usleep");
assertTrue("native target", nativeTarget !== null);
assertTrue("usleep target", usleepTarget !== null);

var nativeAdd = new NativeFunction(nativeTarget, "int", ["int", "int"]);
var usleep = new NativeFunction(usleepTarget, "int", ["uint"]);
var threadId = Process.getCurrentThreadId();
var receiveCount = 0;
var summaryCount = 0;
var eventCount = 0;

Stalker.queueCapacity = 16384;
Stalker.queueDrainInterval = 0;
assertEqual("queueDrainInterval", Stalker.queueDrainInterval, 0);

Stalker.follow(threadId, {
    events: { call: true, ret: true },
    onReceive(events) {
        receiveCount++;
        eventCount += Stalker.parse(events).length;
    },
    onCallSummary(summary) {
        summaryCount++;
        assertTrue("summary shape", summary !== null && typeof summary === "object");
    }
});

for (var index = 0; index !== 8; index++)
    assertEqual("native call " + index, nativeAdd(index, 7), index + 107);
usleep(500000);

assertEqual("automatic onReceive disabled", receiveCount, 0);
assertEqual("automatic onCallSummary disabled", summaryCount, 0);

Stalker.unfollow(threadId);
assertTrue("unfollow delivers onReceive", receiveCount > 0);
assertTrue("unfollow delivers onCallSummary", summaryCount > 0);
assertTrue("unfollow delivers events", eventCount > 0);

for (var gcRound = 0; gcRound !== 8; gcRound++)
    Stalker.garbageCollect();

console.log("[stalker-zero][READY] queueDrainInterval=0 verified");
