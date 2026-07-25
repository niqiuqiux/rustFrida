function pass(name, value) {
    console.log("[goal02][PASS] " + name + "=" + value);
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

assertEqual("Int64 signed wrap", new Int64("0x7fffffffffffffff").add(1), "-9223372036854775808");
assertEqual("Int64 arithmetic shift", new Int64(-1).shr(1), "-1");
assertEqual("UInt64 unsigned wrap", new UInt64("0xffffffffffffffff").add(1), "0");
assertEqual("UInt64 hex", new UInt64("0xffffffffffffffff").toString(16), "ffffffffffffffff");
assertEqual("UInt64 JSON", JSON.stringify(new UInt64("18446744073709551615")), '"18446744073709551615"');

var resolverRejected = false;
try {
    new ApiResolver("objc");
} catch (error) {
    resolverRejected = String(error).indexOf("only 'module' is supported") !== -1;
}
assertTrue("unsupported resolver error", resolverRejected);

var resolver = new ApiResolver("module");
var resolverMatches = resolver.enumerateMatches("exports:librf_goal01_control.so!rf_goal01_open");
assertTrue("module resolver match", resolverMatches.length > 0);
assertTrue("module resolver shape", typeof resolverMatches[0].name === "string" &&
    resolverMatches[0].address !== null && typeof resolverMatches[0].address.toString === "function");

var open = new NativeFunction(requireExport("rf_goal01_open"), "int", []);
var symbol = new NativeFunction(requireExport("rf_goal01_symbol"), "pointer", ["int"]);
var call = new NativeFunction(requireExport("rf_goal01_call"), "int", ["int", "int", "int"]);
var close = new NativeFunction(requireExport("rf_goal01_close"), "int", []);
var jitAlloc = new NativeFunction(requireExport("rf_goal02_jit_alloc"), "pointer", []);
var jitFree = new NativeFunction(requireExport("rf_goal02_jit_free"), "int", ["pointer"]);

assertEqual("fixture open", open(), 0);
var target = symbol(2);
assertTrue("fixture target", !target.isNull());

var targetSymbol = DebugSymbol.fromAddress(target);
assertEqual("DebugSymbol address", targetSymbol.address, target);
assertTrue("DebugSymbol name", targetSymbol.name === "rf_goal01_native_target" ||
    targetSymbol.toString().indexOf("rf_goal01_native_target") !== -1);
assertTrue("DebugSymbol JSON shape", Object.keys(targetSymbol.toJSON()).join(",") ===
    "address,name,moduleName,fileName,lineNumber,column");

var fromName = DebugSymbol.fromName("rf_goal01_native_target");
assertEqual("DebugSymbol.fromName", fromName.address, target);
assertEqual("DebugSymbol.getFunctionByName", DebugSymbol.getFunctionByName("rf_goal01_native_target"), target);
assertTrue("DebugSymbol.findFunctionsNamed", DebugSymbol.findFunctionsNamed("rf_goal01_native_target").length > 0);
assertTrue("DebugSymbol.findFunctionsMatching", DebugSymbol.findFunctionsMatching("rf_goal01_native_*").length > 0);

var noSymbol = DebugSymbol.fromAddress(ptr("0x1"));
assertEqual("unsymbolized address", noSymbol.address, ptr("0x1"));
assertEqual("unsymbolized name", noSymbol.name, null);

var jit = jitAlloc();
assertTrue("anonymous allocation", !jit.isNull());
jit.writeU32(0xd503201f);
assertTrue("anonymous executable memory", Memory.protect(jit, 16, "r-x"));
var jitSymbol = DebugSymbol.fromAddress(jit);
assertEqual("anonymous address", jitSymbol.address, jit);
assertEqual("anonymous free", jitFree(jit), 0);

var instruction = Instruction.parse(target);
assertEqual("Instruction address", instruction.address, target);
assertEqual("Instruction next", instruction.next, target.add(instruction.size));
assertEqual("Instruction ARM64 size", instruction.size, 4);
assertTrue("Instruction mnemonic", instruction.mnemonic.length > 0);
assertTrue("Instruction opStr", typeof instruction.opStr === "string");
assertTrue("Instruction operands", Array.isArray(instruction.operands));
assertTrue("Instruction regsAccessed", Array.isArray(instruction.regsAccessed.read) &&
    Array.isArray(instruction.regsAccessed.written));
assertTrue("Instruction groups", Array.isArray(instruction.groups));
var instructionText = instruction.toString();
assertEqual("Instruction owned lifetime", instruction.toString(), instructionText);
assertTrue("Instruction JSON shape", Object.keys(instruction.toJSON()).join(",") ===
    "address,next,size,mnemonic,opStr,operands,regsAccessed,regsRead,regsWritten,groups");

var hookHits = 0;
var symbolicFrames = [];
var returnSymbol = null;
var listener = Interceptor.attach(target, {
    onEnter() {
        hookHits++;
        var frames = Thread.backtrace(this.context, { backtracer: Backtracer.ACCURATE, limit: 16 });
        symbolicFrames = frames.map(DebugSymbol.fromAddress).map(function (symbol) { return symbol.toString(); });
        returnSymbol = DebugSymbol.fromAddress(this.returnAddress);
        console.log("[goal02][RETURN] " + returnSymbol.toString());
        console.log("[goal02][BACKTRACE] " + symbolicFrames.join(" | "));
    }
});
assertEqual("hook call", call(2, 7, 8), 2015);
assertEqual("hook hit", hookHits, 1);
assertTrue("hook returnAddress captured", returnSymbol !== null);
assertTrue("hook returnAddress symbolized", returnSymbol.toString().indexOf("rf_goal01_call") !== -1);
assertTrue("symbolized backtrace", symbolicFrames.length > 0 && symbolicFrames.some(function (frame) {
    return frame.indexOf("rf_goal01_call") !== -1;
}));
listener.detach();

var staleAddress = target;
assertEqual("fixture close", close(), 0);
var staleSymbol = DebugSymbol.fromAddress(staleAddress);
assertEqual("unloaded address preserved", staleSymbol.address, staleAddress);
assertTrue("unloaded symbol shape", staleSymbol.name === null || typeof staleSymbol.name === "string");
assertTrue("unloaded symbol string", typeof staleSymbol.toString() === "string");
console.log("[goal02][READY] diagnostics verified");
