function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected))
        throw new Error(name + ": expected " + expected + ", got " + actual);
    console.log("[goal01-ab][PASS] " + name + "=" + actual);
}

function assertTrue(name, value) {
    if (!value)
        throw new Error(name + ": expected truthy value");
    console.log("[goal01-ab][PASS] " + name + "=" + value);
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
var cycle = 0;
var target = null;

function openCycle() {
    cycle++;
    assertEqual("open cycle " + cycle, hostOpen(), 0);
    target = hostSymbol(1);
    assertTrue("target cycle " + cycle, !target.isNull());
    console.log("[goal01-ab][TARGET] cycle=" + cycle + " " + target);
}

function verify() {
    assertEqual("hfollow cycle " + cycle, hostCall(1, 7, 0), 1007);
}

function close() {
    assertEqual("close cycle " + cycle, hostClose(), 0);
    assertTrue("mapping removed cycle " + cycle, Module.findByAddress(target) === null);
    console.log("[goal01-ab][CLOSED] cycle=" + cycle);
}

globalThis.goal01Ab = {
    verify: verify,
    close: close,
    open: openCycle
};

openCycle();
