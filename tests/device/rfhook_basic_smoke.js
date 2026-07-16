function pass(name, value) {
    console.log("[smoke][PASS] " + name + "=" + value);
}

function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected)) {
        throw new Error(name + ": expected " + expected + ", got " + actual);
    }
    pass(name, actual);
}

console.log("[smoke] basic memory/hook test loaded");

var block = Memory.alloc(64);
block.writeU8(0xab);
block.add(2).writeU16(0xcdef);
block.add(4).writeU32(0x89abcdef);
block.add(8).writeU64(0x1122334455667788n);
block.add(16).writePointer(block);
block.add(24).writeBytes([0xde, 0xad, 0xbe, 0xef]);

assertEqual("readU8", block.readU8(), 0xab);
assertEqual("readU16", block.add(2).readU16(), 0xcdef);
assertEqual("readU32", block.add(4).readU32(), 0x89abcdefn);
assertEqual("readU64", block.add(8).readU64(), 0x1122334455667788n);
assertEqual("readPointer", block.add(16).readPointer(), block);

var bytes = new Uint8Array(block.add(24).readByteArray(4));
assertEqual("readByteArray", Array.prototype.join.call(bytes, ","), "222,173,190,239");

var utf8 = Memory.allocUtf8String("rustfrida-memory-ok");
assertEqual("readUtf8String", utf8.readUtf8String(), "rustfrida-memory-ok");

var nativeTarget = Module.findExportByName("librfhooktarget.so", "rf_native_add");
if (!nativeTarget) {
    throw new Error("rf_native_add export not found");
}
pass("nativeExport", nativeTarget);

Interceptor.attach(nativeTarget, {
    onEnter(args) {
        this.a = args[0].toInt32();
        this.b = args[1].toInt32();
    },
    onLeave(retval) {
        var original = retval.toInt32();
        retval.replace(original + 2000);
        console.log("[smoke][native-hit] " + this.a + "+" + this.b + "=" + original);
    }
});

Java.ready(function () {
    var Target = Java.use("com.example.rfhooktarget.HookTarget");
    Target.javaCompute.impl = function (value) {
        var original = this.$orig(value);
        console.log("[smoke][java-hit] value=" + value + " original=" + original);
        return original + 1000;
    };
    console.log("[smoke][READY] memory/native/java hooks installed");
});
