function assertTrue(name, value) {
    if (!value)
        throw new Error(name + ": expected truthy value, got " + value);
    console.log("[stalker-native-reload][PASS] " + name + "=" + value);
}

var target = Module.findExportByName("librfhooktarget.so", "rf_native_add");
assertTrue("native target", target !== null);

var callbacks = new CModule(`
typedef struct {
    volatile uint32_t events;
    volatile uint32_t probes;
    volatile uint32_t callouts;
} ReloadState;

void on_event(const void *event, void *cpu_context, void *user_data) {
    ReloadState *state = (ReloadState *) user_data;
    if (event != NULL && cpu_context != NULL)
        state->events++;
}

void on_probe(void *details, void *user_data) {
    ReloadState *state = (ReloadState *) user_data;
    if (details != NULL)
        state->probes++;
}

void on_callout(void *cpu_context, void *user_data) {
    ReloadState *state = (ReloadState *) user_data;
    if (cpu_context != NULL)
        state->callouts++;
}
`);

var state = Memory.alloc(16);
state.writeByteArray(new ArrayBuffer(16));
var nativeAdd = new NativeFunction(target, "int", ["int", "int"]);
var probeId = Stalker.addCallProbe(target, callbacks.on_probe, state);
Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true },
    onEvent: callbacks.on_event,
    data: state,
    transform(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.address.equals(target))
                iterator.putCallout(callbacks.on_callout, state);
            iterator.keep();
        }
    }
});

nativeAdd(3, 4);
assertTrue("active native event", state.readU32() > 0);
assertTrue("active native probe", state.add(4).readU32() === 1);
assertTrue("active native callout", state.add(8).readU32() === 1);
assertTrue("active probe id", probeId > 0);
console.log("[stalker-native-reload][READY] event/probe/callout callbacks intentionally left active");
