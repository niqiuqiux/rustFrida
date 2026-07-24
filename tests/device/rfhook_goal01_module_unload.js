function pass(name, value) {
    console.log("[goal01][PASS] " + name + "=" + value);
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

function requireExport(name) {
    var address = Module.findExportByName("librf_goal01_control.so", name);
    if (address === null)
        address = Module.findExportByName(null, name);
    if (address === null)
        throw new Error("missing host export: " + name);
    return address;
}

var hostOpen = new NativeFunction(requireExport("rf_goal01_open"), "int", []);
var hostSymbol = new NativeFunction(requireExport("rf_goal01_symbol"), "pointer", ["int"]);
var hostCall = new NativeFunction(requireExport("rf_goal01_call"), "int", ["int", "int", "int"]);
var hostClose = new NativeFunction(requireExport("rf_goal01_close"), "int", []);
var hostSleep = new NativeFunction(requireExport("rf_goal01_sleep_ms"), "void", ["uint"]);

var followedThreadId = 0;
var eventBatches = 0;
var eventCount = 0;
var currentCycle = null;
var followed = false;

Stalker.queueDrainInterval = 25;

function startFollowing() {
    if (followed)
        return;
    followedThreadId = Process.getCurrentThreadId();
    Stalker.follow(followedThreadId, {
        events: { call: true, ret: true },
        onReceive(events) {
            eventBatches++;
            eventCount += Stalker.parse(events).length;
        }
    });
    followed = true;
}

function stopFollowing() {
    if (!followed)
        return;
    Stalker.unfollow(followedThreadId);
    Stalker.flush();
    var collected = false;
    for (var round = 0; round !== 100; round++) {
        var result = globalThis.__rf_stalker_garbage_collect();
        if (!result.pending) {
            collected = true;
            break;
        }
        hostSleep(10);
    }
    assertTrue("Stalker GC after unfollow", collected);
    followed = false;
}

function installCycle(number) {
    assertEqual("cycle " + number + " open", hostOpen(), 0);

    var gumTarget = hostSymbol(1);
    var nativeTarget = hostSymbol(2);
    var probeTarget = hostSymbol(3);
    assertTrue("cycle " + number + " Gum target", !gumTarget.isNull());
    assertTrue("cycle " + number + " native target", !nativeTarget.isNull());
    assertTrue("cycle " + number + " probe target", !probeTarget.isNull());

    var nativeHits = 0;
    var nativeListener = Interceptor.attach(nativeTarget, {
        onEnter() {
            nativeHits++;
        },
        onLeave(retval) {
            retval.replace(retval.toInt32() + 40);
        }
    });
    assertEqual("cycle " + number + " native hook result", hostCall(2, 2, 3), 2045);
    assertEqual("cycle " + number + " native hook hit", nativeHits, 1);

    var probeHits = 0;
    var probeId = Stalker.addCallProbe(probeTarget, function (args) {
        probeHits++;
        args[0] = args[0].add(10);
    });
    assertTrue("cycle " + number + " probe id", probeId > 0);
    startFollowing();
    assertEqual("cycle " + number + " probe result", hostCall(3, 4, 5), 3019);
    assertEqual("cycle " + number + " probe hit", probeHits, 1);
    assertEqual("cycle " + number + " remove last probe", Stalker.removeCallProbe(probeId), undefined);
    assertEqual("cycle " + number + " probe restored", hostCall(3, 4, 5), 3009);

    currentCycle = {
        number: number,
        gumTarget: gumTarget,
        nativeTarget: nativeTarget,
        nativeListener: nativeListener
    };
    console.log("[goal01][GUM_TARGET] " + gumTarget);
    return gumTarget.toString();
}

function verifyGumHook() {
    assertTrue("active cycle", currentCycle !== null);
    assertEqual("cycle " + currentCycle.number + " Gum hook call", hostCall(1, 7, 0), 1007);
    console.log("[goal01][GUM_VERIFIED] cycle=" + currentCycle.number);
    return currentCycle.number;
}

function unloadCycle() {
    assertTrue("active cycle before unload", currentCycle !== null);
    var cycle = currentCycle;
    stopFollowing();
    assertEqual("cycle " + cycle.number + " close", hostClose(), 0);
    assertTrue("cycle " + cycle.number + " mapping removed", Module.findByAddress(cycle.gumTarget) === null);
    assertEqual("cycle " + cycle.number + " retired native detach", cycle.nativeListener.detach(), undefined);
    currentCycle = null;
    console.log("[goal01][UNLOADED] cycle=" + cycle.number);
    return cycle.number;
}

function reloadCycle() {
    assertTrue("no active cycle before reload", currentCycle === null);
    return installCycle(2);
}

function finish() {
    assertTrue("active cycle before finish", currentCycle !== null);
    var cycle = currentCycle;
    stopFollowing();
    assertEqual("cycle " + cycle.number + " final close", hostClose(), 0);
    assertTrue("cycle " + cycle.number + " final mapping removed", Module.findByAddress(cycle.gumTarget) === null);
    assertEqual("cycle " + cycle.number + " final native detach", cycle.nativeListener.detach(), undefined);
    currentCycle = null;

    assertTrue("event sink batches", eventBatches > 0);
    assertTrue("event sink events", eventCount > 0);
    console.log("[goal01][READY] unload/reload/re-hook complete");
    return eventCount;
}

globalThis.goal01 = {
    verifyGumHook: verifyGumHook,
    unloadCycle: unloadCycle,
    reloadCycle: reloadCycle,
    finish: finish
};

installCycle(1);
