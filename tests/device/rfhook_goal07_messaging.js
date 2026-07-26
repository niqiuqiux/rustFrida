// Goal 07: timers, the job pump, send/recv, Script and hexdump.
//
// The script finishes its top-level run quickly and lets the timer pump drive
// the rest; the runner waits for the markers each phase prints.

function pass(name, value) {
    console.log("[goal07][PASS] " + name + "=" + value);
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

function fail(message) {
    console.log("[goal07][FAIL] " + message);
    throw new Error(message);
}

// ---------------------------------------------------------------- surface ---

for (const name of [
    "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "setImmediate", "clearImmediate", "send", "recv", "hexdump"
]) {
    assertEqual(name + " is a function", typeof globalThis[name], "function");
}
assertEqual("Script is an object", typeof Script, "object");
assertEqual("Script.runtime", Script.runtime, "QJS");
assertEqual("Script.nextTick is a function", typeof Script.nextTick, "function");
assertEqual("Frida.version", Frida.version, "17.15.5");

assertThrows("setTimeout rejects a non-function", function () {
    return setTimeout(42, 0);
});
assertThrows("recv rejects a non-function", function () {
    return recv("x", 42);
});

// --------------------------------------------------------------- hexdump ----

var sample = Memory.alloc(32);
sample.writeByteArray([0x41, 0x42, 0x43, 0x44, 0x00, 0x01, 0x02, 0x03]);
var dump = hexdump(sample, { length: 8 });
assertTrue("hexdump produced a header", dump.indexOf("0123456789ABCDEF") !== -1);
assertTrue("hexdump rendered the bytes", dump.indexOf("41 42 43 44") !== -1);
assertTrue("hexdump rendered the ASCII column", dump.indexOf("ABCD") !== -1);

// ------------------------------------------------------------------ send ----

send({ phase: "surface", ok: true });
send({ phase: "binary" }, new Uint8Array([1, 2, 3, 4]).buffer);
pass("send accepted a payload and binary data", true);

// ----------------------------------------------------------------- order ----

// Ordering rules under test: nextTick beats a zero-delay timeout, and a shorter
// delay beats a longer one regardless of registration order.
var order = [];

Script.nextTick(function () { order.push("tick"); });
setTimeout(function () { order.push("t20"); }, 20);
setTimeout(function () { order.push("t0"); }, 0);

var cancelled = setTimeout(function () { order.push("cancelled"); }, 5);
clearTimeout(cancelled);

var intervalRuns = 0;
var intervalId = setInterval(function () {
    intervalRuns++;
    if (intervalRuns === 3)
        clearInterval(intervalId);
}, 5);

// A promise settled from a timer only resolves if the job queue is pumped.
var promiseResolved = false;
new Promise(function (resolve) {
    setTimeout(resolve, 10);
}).then(function () {
    promiseResolved = true;
});

setTimeout(function () {
    assertEqual("nextTick ran before the zero-delay timeout", order[0], "tick");
    assertEqual("shorter delay ran first", order[1], "t0");
    assertEqual("longer delay ran last", order[2], "t20");
    assertEqual("cancelled timeout never ran", order.indexOf("cancelled"), -1);
    assertEqual("interval stopped itself", intervalRuns, 3);
    assertTrue("promise settled from a timer", promiseResolved);
    console.log("[goal07][ORDER-READY] timers verified");
    startRecvPhase();
}, 120);

// ------------------------------------------------------------------ recv ----

function startRecvPhase() {
    // One-shot semantics: the first handler is consumed, then re-armed for the
    // typed message.
    recv(function (message) {
        assertEqual("recv got the wildcard message", message.payload, "ping");
        recv("custom", function (typed, data) {
            assertEqual("recv matched the message type", typed.type, "custom");
            assertEqual("recv got the typed payload", typed.payload, "pong");
            assertEqual("recv reports no data for a plain message", data, "null");
            console.log("[goal07][RECV-READY] messaging verified");
            startScanPhase();
        });
        console.log("[goal07][RECV-ARMED] waiting for a typed message");
    });
    console.log("[goal07][RECV-WAITING] waiting for a wildcard message");
}

// -------------------------------------------------------- Memory.scan API ---

function startScanPhase() {
    var haystack = Memory.alloc(4096);
    haystack.add(100).writeByteArray([0x13, 0x37, 0x42]);

    var matches = [];
    var result = Memory.scan(haystack, 4096, "13 37 42", {
        onMatch(address) { matches.push(address); }
    });
    assertTrue("Memory.scan returns a promise", result instanceof Promise);

    result.then(function () {
        assertEqual("scan promise resolved after one match", matches.length, 1);
        assertTrue("scan match is inside the buffer", matches[0].compare(haystack) >= 0);
        // The pattern is validated before the scan starts, so a bad one throws
        // rather than rejecting — same as upstream's `_scan`.
        assertThrows("a bad pattern throws synchronously", function () {
            Memory.scan(haystack, 4096, "zz", {});
        });
    }).then(function () {
        console.log("[goal07][SCAN-READY] Memory.scan promise verified");
        startTeardownPhase();
    }).catch(function (error) {
        fail("scan phase failed: " + error);
    });
}

// -------------------------------------------------------------- teardown ----

function startTeardownPhase() {
    // A repeating timer left running here must be cancelled by %reload and by
    // shutdown; the runner checks that no stale callback logs afterwards.
    setInterval(function () {
        console.log("[goal07][HEARTBEAT] still running");
    }, 500);
    console.log("[goal07][READY] messaging and timers verified");
}
