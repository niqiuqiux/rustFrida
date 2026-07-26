// Goal 06: Memory.alloc options, patchCode, async scan, findPointers,
// checkCodePointer and MemoryAccessMonitor.

function pass(name, value) {
    console.log("[goal06][PASS] " + name + "=" + value);
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

function assertThrows(name, fn) {
    try {
        fn();
    } catch (error) {
        pass(name, "threw: " + error.message);
        return;
    }
    throw new Error(name + ": expected an exception");
}

function requireExport(name) {
    var address = Module.findExportByName("librf_goal06_memory.so", name);
    if (address === null)
        address = Module.findExportByName(null, name);
    if (address === null)
        throw new Error("missing Goal 06 export: " + name);
    return address;
}

var init = new NativeFunction(requireExport("rf_goal06_init"), "void", []);
var patchTargetAddress = requireExport("rf_goal06_patch_target");
var patchTarget = new NativeFunction(patchTargetAddress, "int", []);
var haystack = new NativeFunction(requireExport("rf_goal06_haystack"), "pointer", [])();
var haystackSize = new NativeFunction(requireExport("rf_goal06_haystack_size"), "uint64", [])();
var pointerSlots = new NativeFunction(requireExport("rf_goal06_pointer_slots"), "pointer", [])();
var pointerSlotsSize = new NativeFunction(requireExport("rf_goal06_pointer_slots_size"), "uint64", [])();
var monitored = new NativeFunction(requireExport("rf_goal06_monitored"), "pointer", [])();
var monitoredSize = new NativeFunction(requireExport("rf_goal06_monitored_size"), "uint64", [])();
var touchMonitored = new NativeFunction(requireExport("rf_goal06_touch_monitored"), "uint8", ["uint64"]);
var startToucher = new NativeFunction(requireExport("rf_goal06_start_toucher"), "int", []);
var stopToucher = new NativeFunction(requireExport("rf_goal06_stop_toucher"), "void", []);
var touchRounds = new NativeFunction(requireExport("rf_goal06_touch_rounds"), "uint64", []);

// Reset fixture state so a %reload starts from the same place. The patch below
// outlives the script, so restore the original body too; on the first run this
// writes back what is already there.
init();
// mov w0, #0x1111 ; ret
var originalBody = [0x20, 0x22, 0x82, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

Memory.patchCode(requireExport("rf_goal06_patch_target"), originalBody.length, function (code) {
    code.writeByteArray(originalBody);
});

// ------------------------------------------------------------------ alloc ---

var pageSize = Process.pageSize;
assertTrue("page size is a power of two", pageSize > 0 && (pageSize & (pageSize - 1)) === 0);

// Sub-page allocations come from the heap and stay read/write.
var small = Memory.alloc(64);
small.writeU32(0xdeadbeef);
assertEqual("sub-page alloc is writable", small.readU32(), 0xdeadbeef);
assertEqual("sub-page alloc is zeroed", small.add(8).readU32(), 0);

// Whole-page allocations are mapped with the requested protection.
var page = Memory.alloc(pageSize);
assertTrue("page alloc is page aligned", page.and(ptr(pageSize - 1)).isNull());
page.writeU32(0x1234);
assertEqual("page alloc is writable", page.readU32(), 0x1234);
assertEqual("page alloc protection", Memory.queryProtection(page).slice(0, 2), "rw");

var executable = Memory.alloc(pageSize, { protection: "rwx" });
assertEqual("executable alloc protection", Memory.queryProtection(executable), "rwx");

assertThrows("executable sub-page alloc is rejected", function () {
    return Memory.alloc(64, { protection: "rwx" });
});
assertThrows("zero size is rejected", function () {
    return Memory.alloc(0);
});

// near/maxDistance must land inside the requested window.
var nearTarget = patchTargetAddress;
var maxDistance = 128 * 1024 * 1024;
var nearby = Memory.alloc(pageSize, { near: nearTarget, maxDistance: maxDistance, protection: "rwx" });
var distance = nearby.compare(nearTarget) >= 0 ? nearby.sub(nearTarget) : nearTarget.sub(nearby);
assertTrue("near alloc is inside maxDistance", distance.compare(ptr(maxDistance)) <= 0);
assertTrue("near alloc is page aligned", nearby.and(ptr(pageSize - 1)).isNull());
assertEqual("near alloc protection", Memory.queryProtection(nearby), "rwx");
assertThrows("near alloc requires a page multiple", function () {
    return Memory.alloc(64, { near: nearTarget, maxDistance: maxDistance });
});

// ------------------------------------------------------------- patchCode ----

assertEqual("target before patch", patchTarget(), 0x1111);

// mov w0, #0x2222 ; ret
var patched = [0x40, 0x44, 0x84, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
Memory.patchCode(patchTargetAddress, patched.length, function (code) {
    code.writeByteArray(patched);
});
assertEqual("target after patch", patchTarget(), 0x2222);
assertEqual("patched pages are executable again", Memory.queryProtection(patchTargetAddress).slice(2), "x");

// An exception inside apply must propagate but still restore protection.
assertThrows("patchCode propagates apply errors", function () {
    Memory.patchCode(patchTargetAddress, 4, function () {
        throw new Error("apply failed");
    });
});
assertEqual("protection restored after a failed apply", Memory.queryProtection(patchTargetAddress).slice(2), "x");
assertEqual("target still patched after failed apply", patchTarget(), 0x2222);

// --------------------------------------------------------- findPointers -----

var matches = Memory.findPointers(
    [{ base: pointerSlots, size: pointerSlotsSize }],
    [patchTargetAddress]
);
assertEqual("findPointers found both slots", matches.length, 2);
assertTrue("findPointers reports the value", matches[0].value.equals(patchTargetAddress));
assertEqual(
    "findPointers slots are pointer aligned",
    matches[1].address.sub(pointerSlots).toUInt32() % Process.pointerSize,
    0
);

var masked = Memory.findPointers(
    [{ base: pointerSlots, size: pointerSlotsSize }],
    [ptr(0)],
    { mask: ptr(0) }
);
assertTrue("findPointers honours the mask", masked.length >= 2);

// ------------------------------------------------------ checkCodePointer ----

var firstByte = Memory.checkCodePointer(patchTargetAddress);
assertTrue("checkCodePointer returns a byte", Number.isInteger(firstByte) && firstByte >= 0 && firstByte <= 255);
assertEqual("checkCodePointer matches a direct read", firstByte, patchTargetAddress.readU8());
assertThrows("checkCodePointer rejects an unmapped address", function () {
    return Memory.checkCodePointer(ptr("0x10"));
});

// --------------------------------------------------------------- scanSync ---

var pattern = "13 37 42";
var syncMatches = Memory.scanSync(haystack, haystackSize, pattern);
assertEqual("scanSync found both needles", syncMatches.length, 2);

// ----------------------------------------------------------- async scan -----

var asyncMatches = [];
var scanCompleted = false;
var scanError = null;

Memory.scan(haystack, haystackSize, pattern, {
    onMatch(address, size) {
        asyncMatches.push({ address: address, size: size });
    },
    onError(reason) {
        scanError = reason;
    },
    onComplete() {
        scanCompleted = true;
    }
});

// Background work re-enters JavaScript through the engine guard, so yielding
// via a native call is what lets it make progress. The call must not touch the
// monitored pages: a fault inside a NativeFunction call is claimed by the
// agent's handling for that call rather than by the monitor.
function waitFor(predicate, timeoutMs) {
    var deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (predicate())
            return true;
        touchRounds();
    }
    return predicate();
}

assertTrue("async scan completed", waitFor(function () { return scanCompleted; }, 5000));
if (scanError !== null)
    throw new Error("async scan reported an error: " + scanError);
pass("async scan reported no error", true);
assertEqual("async scan found both needles", asyncMatches.length, 2);
assertEqual("async scan reports the pattern size", asyncMatches[0].size, 3);
assertTrue(
    "async scan agrees with scanSync",
    asyncMatches[0].address.equals(syncMatches[0].address) && asyncMatches[1].address.equals(syncMatches[1].address)
);

assertThrows("async scan rejects a bad pattern", function () {
    Memory.scan(haystack, haystackSize, "zz", { onComplete() {} });
});

// -------------------------------------------------- MemoryAccessMonitor -----

assertEqual("MemoryAccessMonitor.enable is a function", typeof MemoryAccessMonitor.enable, "function");
assertEqual("MemoryAccessMonitor.disable is a function", typeof MemoryAccessMonitor.disable, "function");

var accesses = [];

// The monitor reports faults taken by the target's own code, so the touches are
// driven by a fixture thread rather than a NativeFunction call: a fault inside
// such a call is claimed by the agent's own handling for that call.
assertTrue("toucher thread started", startToucher() === 1);

MemoryAccessMonitor.enable([{ base: monitored, size: monitoredSize }], {
    onAccess(details) {
        accesses.push(details);
    }
});

var protectionWhileMonitored = Memory.queryProtection(monitored);
assertTrue(
    "monitor reported an access",
    waitFor(function () { return accesses.length > 0; }, 5000)
);
var access = accesses[0];
assertTrue("access has an address", access.address instanceof NativePointer);
assertTrue("access has a from pointer", access.from instanceof NativePointer);
assertTrue(
    "access operation is known",
    ["read", "write", "execute"].indexOf(access.operation) !== -1
);
assertTrue("access has a thread id", Number.isInteger(access.threadId) && access.threadId > 0);
assertTrue("access reports page totals", access.pagesTotal > 0);
assertTrue(
    "access address is inside the monitored range",
    access.address.compare(monitored) >= 0 && access.address.compare(monitored.add(monitoredSize)) < 0
);

// Monitoring works by removing page permissions, so the range must be
// readable and writable again once the monitor is gone. Checking the mapping
// directly is stronger than waiting on the toucher: while monitoring is on,
// every fault re-enters JavaScript synchronously, which slows the watched
// thread to a crawl.
assertEqual("monitored pages lose write access while monitored", protectionWhileMonitored.slice(1, 2), "-");

MemoryAccessMonitor.disable();
var afterDisable = accesses.length;
// Every page must come back, not just the first: a page the monitor never
// saw accessed would otherwise stay unwritable with no handler left to fault
// into.
var stillProtected = [];
for (var offset = 0; offset < monitoredSize; offset += pageSize) {
    var protection = Memory.queryProtection(monitored.add(offset));
    if (protection !== "rw-")
        stillProtected.push("+0x" + offset.toString(16) + "=" + protection);
}
assertEqual("every monitored page is writable again after disable", stillProtected.join(","), "");

// Give the toucher a chance to run unmonitored; no further callbacks may fire.
for (var yieldRound = 0; yieldRound !== 200; yieldRound++)
    touchRounds();
assertEqual("monitor stopped after disable", accesses.length, afterDisable);

// Disabling twice must stay a no-op rather than tearing down twice.
MemoryAccessMonitor.disable();
pass("monitor tolerates a second disable", true);

assertThrows("monitor rejects an empty range list", function () {
    MemoryAccessMonitor.enable([], { onAccess() {} });
});

// Only signal the thread: joining here would block on a round that is still
// paying for the monitor's synchronous callbacks.
stopToucher();
pass("toucher thread stopped", true);

console.log("[goal06][READY] Memory advanced APIs verified");
