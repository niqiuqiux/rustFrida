function pass(name, value) {
    console.log("[qbdi-smoke][PASS] " + name + "=" + value);
}

function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected)) {
        throw new Error(name + ": expected " + expected + ", got " + actual);
    }
    pass(name, actual);
}

function requireSuccess(name, value) {
    if (!value) {
        throw new Error(name + " failed: " + qbdi.lastError());
    }
    pass(name, value);
}

var target = Module.findExportByName("librfhooktarget.so", "rf_native_add");
if (!target) {
    throw new Error("rf_native_add export not found");
}
if (typeof qbdi === "undefined") {
    throw new Error("qbdi API unavailable");
}

function traceCall(label, outDir, left, right, expected) {
    var vm = qbdi.newVM();
    var registered = false;
    try {
        requireSuccess(label + ".addModule", qbdi.addInstrumentedModuleFromAddr(vm, target));
        requireSuccess(label + ".allocateStack", qbdi.allocateVirtualStack(vm, 0x100000));
        requireSuccess(label + ".register", qbdi.registerTraceCallbacks(vm, target, outDir));
        registered = true;

        var result = qbdi.call(vm, target, left, right);
        if (result === null) {
            throw new Error(label + ".call failed: " + qbdi.lastError());
        }
        assertEqual(label + ".return", result, expected);
    } finally {
        if (registered) {
            requireSuccess(label + ".unregister", qbdi.unregisterTraceCallbacks(vm));
        }
        requireSuccess(label + ".destroy", qbdi.destroyVM(vm));
    }

    var bundle = File.readAllBytes(outDir + "/trace_bundle.pb");
    if (bundle.byteLength <= 4) {
        throw new Error(label + ".bundle is empty");
    }
    pass(label + ".bundleBytes", bundle.byteLength);
}

var base = "/data/user/0/com.example.rfhooktarget/files/.rustfrida";
traceCall("first", base + "/qbdi_smoke_first", 11, 22, 133);
traceCall("second", base + "/qbdi_smoke_second", 5, 6, 111);
console.log("[qbdi-smoke][READY] two independent trace bundles generated");
