function pass(name, value) {
    console.log("[stalker-native][PASS] " + name + "=" + value);
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

var callbacks = new CModule(`
typedef struct {
    volatile uint32_t event_count;
    volatile uint32_t exec_count;
    volatile uint32_t probe_count;
    volatile uint32_t context_count;
    volatile uint32_t last_event_type;
} CallbackState;

void on_event(const void *raw_event, void *cpu_context, void *user_data) {
    const uint32_t event_type = *(const uint32_t *) raw_event;
    CallbackState *state = (CallbackState *) user_data;
    state->event_count++;
    if (event_type == 4)
        state->exec_count++;
    if (cpu_context != NULL)
        state->context_count++;
    state->last_event_type = event_type;
}

void on_probe(void *details, void *user_data) {
    CallbackState *state = (CallbackState *) user_data;
    if (details != NULL)
        state->probe_count++;
}
`);

var state = Memory.alloc(32);
state.writeByteArray(new ArrayBuffer(32));
var nativeAdd = new NativeFunction(target, "int", ["int", "int"]);
var baseline = nativeAdd(7, 8);
var threadId = Process.getCurrentThreadId();

var mixedDeliveryRejected = false;
try {
    Stalker.follow(threadId, {
        events: { exec: true },
        onReceive() {},
        onEvent: callbacks.on_event,
        data: state
    });
} catch (error) {
    mixedDeliveryRejected = /precludes/.test(String(error));
}
assertTrue("native delivery excludes queued callbacks", mixedDeliveryRejected);

var nullProbeRejected = false;
try {
    Stalker.addCallProbe(target, NULL, state);
} catch (error) {
    nullProbeRejected = /must not be NULL/.test(String(error));
}
assertTrue("NULL native probe rejected", nullProbeRejected);

var probeId = Stalker.addCallProbe(target, callbacks.on_probe, state);
assertTrue("native probe id", Number.isInteger(probeId) && probeId > 0);

Stalker.follow(threadId, {
    events: { call: true, exec: true },
    onEvent: callbacks.on_event,
    data: state
});
assertEqual("native call result", nativeAdd(7, 8), baseline);
Stalker.unfollow(threadId);
for (var round = 0; round !== 8; round++)
    Stalker.garbageCollect();

var eventCount = state.readU32();
var execCount = state.add(4).readU32();
var probeCount = state.add(8).readU32();
var contextCount = state.add(12).readU32();
var lastEventType = state.add(16).readU32();
assertTrue("native event callback", eventCount > 0);
assertTrue("native exec callback", execCount > 0);
assertEqual("native call probe", probeCount, 1);
assertTrue("native cpu context", contextCount > 0);
assertTrue("native event type", [1, 2, 4, 8, 16].indexOf(lastEventType) !== -1);

Stalker.removeCallProbe(probeId);
var eventsAfterUnfollow = state.readU32();
var probesAfterRemoval = state.add(8).readU32();
assertEqual("post-cleanup call result", nativeAdd(7, 8), baseline);
assertEqual("events stop after unfollow", state.readU32(), eventsAfterUnfollow);
assertEqual("probe stops after removal", state.add(8).readU32(), probesAfterRemoval);
assertEqual("idempotent native probe removal", Stalker.removeCallProbe(probeId), undefined);

console.log("[stalker-native][READY] native onEvent/data and call probe callbacks verified");
