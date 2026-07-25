function pass(name, value) {
    console.log("[goal04][PASS] " + name + "=" + value);
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

function assertNear(name, actual, expected) {
    if (Math.abs(actual - expected) > 0.000001)
        throw new Error(name + ": expected " + expected + ", got " + actual);
    pass(name, actual);
}

function requireExport(name) {
    var address = Module.findExportByName("librf_goal04_native_abi.so", name);
    if (address === null)
        address = Module.findExportByName(null, name);
    if (address === null)
        throw new Error("missing Goal 04 export: " + name);
    return address;
}

var callBinary = new NativeFunction(requireExport("rf_goal04_call_binary"), "int", ["pointer", "int", "int"]);
var callMixed = new NativeFunction(requireExport("rf_goal04_call_mixed"), "double", ["pointer"]);
var callFloat = new NativeFunction(requireExport("rf_goal04_call_float"), "float", ["pointer", "float"]);
var callGpr9 = new NativeFunction(requireExport("rf_goal04_call_gpr9"), "uint64", ["pointer"]);
var callFpr9 = new NativeFunction(requireExport("rf_goal04_call_fpr9"), "double", ["pointer"]);
var callThread = new NativeFunction(requireExport("rf_goal04_call_thread"), "int", ["pointer", "int"]);
var callErrno = new NativeFunction(requireExport("rf_goal04_call_errno"), "int", ["pointer", "int"]);
var generation = new NativeFunction(requireExport("rf_goal04_saved_generation"), "int", []);
var invokeSaved = new NativeFunction(requireExport("rf_goal04_invoke_saved"), "int", ["int"]);
var saveCallback = new NativeFunction(requireExport("rf_goal04_save_callback"), "void", ["pointer"]);

var smallPairType = ["int32", "int32"];
var nestedPayloadType = [smallPairType, "double", "uint64"];
var variadicInts = new NativeFunction(requireExport("rf_goal04_variadic_ints"), "int", ["int", "...", "uint8", "uint16"]);
var variadicDoubles = new NativeFunction(requireExport("rf_goal04_variadic_doubles"), "double", ["int", "...", "float"]);
var smallPair = new NativeFunction(requireExport("rf_goal04_small_pair"), smallPairType, [smallPairType, "int32"]);
var nestedPayload = new NativeFunction(requireExport("rf_goal04_nested_payload"), nestedPayloadType, [nestedPayloadType]);
var callSmallPair = new NativeFunction(requireExport("rf_goal04_call_small_pair"), smallPairType, ["pointer"]);
var callNestedPayload = new NativeFunction(requireExport("rf_goal04_call_nested_payload"), nestedPayloadType, ["pointer"]);
var boolNot = new NativeFunction(requireExport("rf_goal04_bool_not"), "bool", ["bool"]);

assertTrue("NativeFunction is NativePointer", callBinary instanceof NativePointer);
assertTrue("NativeFunction instance shape", callBinary instanceof NativeFunction);

var replacementAddress = requireExport("rf_goal04_replace_target");
var probeTarget = requireExport("rf_goal04_probe_target");
var unarySignature = new NativeFunction(requireExport("rf_goal04_set_errno"), "int", ["int"]);
assertEqual("NativeFunction.call receiver override", unarySignature.call(replacementAddress, 7), 8);
assertEqual("NativeFunction.apply receiver override", unarySignature.apply(replacementAddress, [8]), 9);

var previousGeneration = generation();
if (previousGeneration === 0) {
    assertEqual("initial saved callback", invokeSaved(3), -7777);
} else {
    assertEqual("retired callback returns zero", invokeSaved(3), 0);
}

var binary = new NativeCallback(function(left, right) {
    return left * 10 + right;
}, "int", ["int", "int"]);
assertTrue("NativeCallback is NativePointer", binary instanceof NativePointer);
assertEqual("integer callback", callBinary(binary, 4, 2), 42);
assertEqual("NativeFunction.call", callBinary.call(null, binary, 4, 2), 42);
assertEqual("NativeFunction.apply", callBinary.apply(null, [binary, 4, 2]), 42);

var reentrant = new NativeCallback(function(left, right) {
    return unarySignature(left) + right;
}, "int", ["int", "int"]);
assertEqual("callback reenters NativeFunction", callBinary(reentrant, 20, 2), 42);

var mixed = new NativeCallback(function(a, b, c, d) {
    return a + b + c + d;
}, "double", ["int", "double", "float", "int"]);
assertNear("mixed callback", callMixed(mixed), 19.75);

var floatCallback = new NativeCallback(function(value) {
    return value * 2;
}, "float", ["float"]);
assertNear("float callback", callFloat(floatCallback, 1.25), 2.5);

var gpr9 = new NativeCallback(function(a, b, c, d, e, f, g, h, i) {
    return a + b + c + d + e + f + g + h + i;
}, "uint64", ["uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64"]);
assertEqual("GPR stack spill", callGpr9(gpr9), 45);

var fpr9 = new NativeCallback(function(a, b, c, d, e, f, g, h, i) {
    return a + b + c + d + e + f + g + h + i;
}, "double", ["double", "double", "double", "double", "double", "double", "double", "double", "double"]);
assertNear("FPR stack spill", callFpr9(fpr9), 45);

var threaded = new NativeCallback(function(value) {
    return value + 5;
}, "int", ["int"]);
assertEqual("pthread callback", callThread(threaded, 37), 42);

var errnoCallback = new NativeCallback(function() {
    assertEqual("callback errno input", this.errno, 1300);
    this.errno = this.errno + 37;
}, "void", []);
assertEqual("callback errno output", callErrno(errnoCallback, 1300), 1337);

var systemSetErrno = new SystemFunction(requireExport("rf_goal04_set_errno"), "int", ["int"], {
    abi: "sysv",
    traps: "none"
});
var systemResult = systemSetErrno(37);
assertTrue("SystemFunction is NativePointer", systemSetErrno instanceof NativePointer);
assertTrue("SystemFunction instance shape", systemSetErrno instanceof SystemFunction);
assertEqual("SystemFunction value", systemResult.value, 74);
assertEqual("SystemFunction errno", systemResult.errno, 37);

assertEqual("variadic integer promotion", variadicInts(2, 250, 60000), 60250);
assertNear("variadic float promotion", variadicDoubles(3, 1.25, 2.5, 3.75), 7.5);

var smallPairResult = smallPair([10, 20], 3);
assertEqual("small struct return left", smallPairResult[0], 13);
assertEqual("small struct return right", smallPairResult[1], 17);
var nestedResult = nestedPayload([[7, 8], 2.25, 40]);
assertEqual("nested struct return left", nestedResult[0][0], 8);
assertEqual("nested struct return right", nestedResult[0][1], 10);
assertNear("nested struct return double", nestedResult[1], 4.5);
assertEqual("nested struct return uint64", nestedResult[2], 43);

var smallPairCallback = new NativeCallback(function(value, delta) {
    return [value[0] + delta, value[1] - delta];
}, smallPairType, [smallPairType, "int32"]);
var callbackSmallPairResult = callSmallPair(smallPairCallback);
assertEqual("small struct callback left", callbackSmallPairResult[0], 25);
assertEqual("small struct callback right", callbackSmallPairResult[1], 17);

var nestedPayloadCallback = new NativeCallback(function(value) {
    return [[value[0][0] + 10, value[0][1] + 20], value[1] * 3, value[2] + 40];
}, nestedPayloadType, [nestedPayloadType]);
var callbackNestedResult = callNestedPayload(nestedPayloadCallback);
assertEqual("nested struct callback left", callbackNestedResult[0][0], 14);
assertEqual("nested struct callback right", callbackNestedResult[0][1], 25);
assertNear("nested struct callback double", callbackNestedResult[1], 4.5);
assertEqual("nested struct callback uint64", callbackNestedResult[2], 70);

assertEqual("bool false return", boolNot(true), false);
assertEqual("bool true return", boolNot(false), true);

var exclusiveCall = new NativeFunction(requireExport("rf_goal04_set_errno"), "int", ["int"], {
    scheduling: "exclusive",
    exceptions: "propagate",
    traps: "none"
});
assertEqual("exclusive propagate call", exclusiveCall(21), 42);
var trapAllCall = new NativeFunction(requireExport("rf_goal04_replace_target"), "int", ["int"], {
    traps: "all"
});
assertEqual("traps all call", trapAllCall(41), 42);

var faultCall = new NativeFunction(requireExport("rf_goal04_fault"), "int", [], {
    exceptions: "steal"
});
var faultType = "none";
try {
    faultCall();
} catch (error) {
    faultType = error.type;
}
assertEqual("native fault stolen", faultType, "access-violation");

var rejectedOptions = 0;
try {
    new NativeCallback(function() {}, "int", [], "win64");
} catch (error) {
    rejectedOptions++;
}
try {
    new NativeCallback(function() {}, "int", ["int", "...", "int"]);
} catch (error) {
    rejectedOptions++;
}
assertEqual("unsupported callback ABI combinations rejected", rejectedOptions, 2);

var replaceTarget = requireExport("rf_goal04_replace_target");
var callReplaceTarget = new NativeFunction(replaceTarget, "int", ["int"]);
var callProbeTarget = new NativeFunction(probeTarget, "int", ["int"]);
var replacement = new NativeCallback(function(value) {
    return value + 100;
}, "int", ["int"]);
Interceptor.replace(replaceTarget, replacement);
assertEqual("Interceptor NativeCallback replacement", callReplaceTarget(7), 107);
Interceptor.revert(replaceTarget);
assertEqual("Interceptor replacement revert", callReplaceTarget(7), 8);

var saved = new NativeCallback(function(value) {
    return value + 9;
}, "int", ["int"]);
saveCallback(saved);
assertEqual("saved callback current runtime", invokeSaved(33), 42);

(function() {
    var gcOwned = new NativeCallback(function(value) {
        return value + 11;
    }, "int", ["int"]);
    saveCallback(gcOwned);
})();
gc();
assertEqual("native-held callback survives GC", invokeSaved(31), 42);

var probeCount = 0;
var probeId = (function() {
    var probe = new NativeCallback(function() {
        probeCount++;
    }, "void", ["pointer", "pointer"]);
    return Stalker.addCallProbe(probeTarget, probe);
})();
gc();
var probeThreadId = Process.getCurrentThreadId();
Stalker.follow(probeThreadId, { events: { call: true } });
assertEqual("Stalker probe target call", callProbeTarget(40), 42);
Stalker.unfollow(probeThreadId);
assertEqual("Stalker-held callback survives GC", probeCount, 1);
Stalker.removeCallProbe(probeId);
Stalker.garbageCollect();

console.log("[goal04][READY] native ABI verified generation=" + generation());
