function pass(name, value) {
    console.log("[smoke][PASS] " + name + "=" + value);
}

function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected)) {
        throw new Error(name + ": expected " + expected + ", got " + actual);
    }
    pass(name, actual);
}

function assertTrue(name, value) {
    if (!value) {
        throw new Error(name + ": expected truthy value, got " + value);
    }
    pass(name, value);
}

console.log("[smoke] basic memory/hook test loaded");

var block = Memory.alloc(128);
block.writeU8(0xab);
block.add(2).writeU16(0xcdef);
block.add(4).writeU32(0x89abcdef);
block.add(8).writeU64(0x1122334455667788n);
block.add(16).writePointer(block);
block.add(24).writeBytes([0xde, 0xad, 0xbe, 0xef]);
block.add(32).writeS8(-2);
block.add(34).writeShort(-1234);
block.add(36).writeInt(-12345678);
block.add(40).writeS64(-0x102030405060708n);
block.add(48).writeFloat(1.25);
block.add(56).writeDouble(-9.5);

assertEqual("readU8", block.readU8(), 0xab);
assertEqual("readU16", block.add(2).readU16(), 0xcdef);
assertEqual("readU32", block.add(4).readU32(), 0x89abcdef);
assertEqual("readU64", block.add(8).readU64(), 0x1122334455667788n);
assertEqual("readPointer", block.add(16).readPointer(), block);
assertEqual("readS8", block.add(32).readS8(), -2);
assertEqual("readShort", block.add(34).readShort(), -1234);
assertEqual("readInt", block.add(36).readInt(), -12345678);
assertEqual("readS64", block.add(40).readS64(), -0x102030405060708n);
assertEqual("readFloat", block.add(48).readFloat(), 1.25);
assertEqual("readDouble", block.add(56).readDouble(), -9.5);

var bytes = new Uint8Array(block.add(24).readByteArray(4));
assertEqual("readByteArray", Array.prototype.join.call(bytes, ","), "222,173,190,239");

var utf8 = Memory.allocUtf8String("rustfrida-memory-ok");
assertEqual("readUtf8String", utf8.readUtf8String(), "rustfrida-memory-ok");

var utf16 = Memory.allocUtf16String("rustfrida-utf16-ok");
assertEqual("readUtf16String", utf16.readUtf16String(), "rustfrida-utf16-ok");

var utf16Buffer = Memory.alloc(64);
utf16Buffer.writeUtf16String("write-utf16-ok");
assertEqual("writeUtf16String", utf16Buffer.readUtf16String(), "write-utf16-ok");

var copied = Memory.alloc(4);
Memory.copy(copied, block.add(24), 4);
assertEqual(
    "Memory.copy",
    Array.prototype.join.call(new Uint8Array(copied.readByteArray(4)), ","),
    "222,173,190,239"
);
var duplicated = Memory.dup(block.add(24), 4);
assertEqual(
    "Memory.dup",
    Array.prototype.join.call(new Uint8Array(duplicated.readByteArray(4)), ","),
    "222,173,190,239"
);

var matches = Memory.scanSync(block.add(24), 4, "d? ad ?e ef : ff ff ff ff");
assertEqual("Memory.scanSync count", matches.length, 1);
assertTrue("Memory.scanSync address", matches[0].address.equals(block.add(24)));
assertEqual("Memory.scanSync size", matches[0].size, 4);
assertEqual("Memory.queryProtection", Memory.queryProtection(block), "rw-");

assertTrue("NULL.isNull", NULL.isNull());
assertTrue("NativePointer.equals", block.equals(ptr(block.toString())));
assertEqual("NativePointer.compare", ptr("0x20").compare(ptr("0x10")), 1);
assertEqual("NativePointer.and", ptr("0xff").and(0x0f).toString(), "0xf");
assertEqual("NativePointer.or", ptr("0xf0").or(0x0f).toString(), "0xff");
assertEqual("NativePointer.xor", ptr("0xff").xor(0x0f).toString(), "0xf0");
assertEqual("NativePointer.shl", ptr("0x1").shl(4).toString(), "0x10");
assertEqual("NativePointer.shr", ptr("0x10").shr(4).toString(), "0x1");
assertEqual("NativePointer.toString radix", ptr("0xff").toString(10), "255");
assertTrue("NativePointer.toMatchPattern", block.toMatchPattern().length > 0);

var badAddressRejected = false;
try {
    ptr("0x1").readU8();
} catch (e) {
    badAddressRejected = true;
}
assertTrue("invalid memory read throws", badAddressRejected);

function runNativeTests() {
var nativeTarget = Module.findExportByName("librfhooktarget.so", "rf_native_add");
if (!nativeTarget) {
    throw new Error("rf_native_add export not found");
}
pass("nativeExport", nativeTarget);

var nativeAdd = new NativeFunction(nativeTarget, "int", ["int", "int"]);
var baseline23 = nativeAdd(2, 3);
var baseline33 = nativeAdd(3, 3);
var baseline45 = nativeAdd(4, 5);

assertTrue("Stalker.supported", Stalker.supported);
var originalTrustThreshold = Stalker.trustThreshold;
Stalker.trustThreshold = originalTrustThreshold;
assertEqual("Stalker.trustThreshold", Stalker.trustThreshold, originalTrustThreshold);
Stalker.queueCapacity = 4096;
Stalker.queueDrainInterval = 50;
assertEqual("Stalker.queueCapacity", Stalker.queueCapacity, 4096);
assertEqual("Stalker.queueDrainInterval", Stalker.queueDrainInterval, 50);

var stalkerBatchCount = 0;
var stalkerEventCount = 0;
var stalkerRowsValid = true;
var stalkerThreadId = Process.getCurrentThreadId();
var firstProbeHits = 0;
var secondProbeHits = 0;
var probeArgsValid = true;
var firstProbeId = Stalker.addCallProbe(nativeTarget, function (args) {
    firstProbeHits++;
    probeArgsValid = probeArgsValid && args[0].toInt32() === 4 && args[1].toInt32() === 5;
    args[0] = args[0].add(10);
});
var secondProbeId = Stalker.addCallProbe(nativeTarget, function (args) {
    secondProbeHits++;
    var expectedFirst = secondProbeHits === 1 ? 14 : 4;
    probeArgsValid = probeArgsValid && args[0].toInt32() === expectedFirst && args[1].toInt32() === 5;
    args[1] = args[1].add(20);
});
assertTrue("Stalker call probe ids", firstProbeId > 0 && secondProbeId > 0 && firstProbeId !== secondProbeId);
Stalker.follow(stalkerThreadId, {
    events: { call: true, ret: true },
    onReceive(events) {
        stalkerBatchCount++;
        var rows = Stalker.parse(events, { annotate: true, stringify: true });
        stalkerEventCount += rows.length;
        stalkerRowsValid = stalkerRowsValid && rows.every(function (row) {
            return row[0] === "call" || row[0] === "ret";
        });
    }
});
assertEqual("Stalker chained call probe result", nativeAdd(4, 5), baseline45 + 30);
assertEqual("Stalker first call probe hit", firstProbeHits, 1);
assertEqual("Stalker second call probe hit", secondProbeHits, 1);
assertTrue("Stalker call probe args", probeArgsValid);
assertEqual("Stalker remove first call probe", Stalker.removeCallProbe(firstProbeId), undefined);
assertEqual("Stalker remaining call probe result", nativeAdd(4, 5), baseline45 + 20);
assertEqual("Stalker removed call probe stays detached", firstProbeHits, 1);
assertEqual("Stalker remaining call probe hit", secondProbeHits, 2);
assertTrue("Stalker remaining call probe args", probeArgsValid);
assertEqual("Stalker remove second call probe", Stalker.removeCallProbe(secondProbeId), undefined);
assertEqual("Stalker call probes restore target", nativeAdd(4, 5), baseline45);
assertEqual("Stalker idempotent call probe removal", Stalker.removeCallProbe(firstProbeId), undefined);
Stalker.unfollow(stalkerThreadId);
Stalker.flush();
for (var stalkerGcRound = 0; stalkerGcRound < 8; stalkerGcRound++) {
    Stalker.garbageCollect();
}
assertTrue("Stalker onReceive batch", stalkerBatchCount > 0);
assertTrue("Stalker parsed events", stalkerEventCount > 0);
assertTrue("Stalker event shape", stalkerRowsValid);

var interceptorEvents = [];
var interceptorState = {
    metadataOk: false,
    sharedThisOk: false,
    secondSawFirstArgChange: false,
    secondSawFirstRetvalChange: false
};

var firstListener = Interceptor.attach(nativeTarget, {
    onEnter(args) {
        interceptorEvents.push("first-enter");
        interceptorState.metadataOk =
            this.returnAddress !== null &&
            !this.returnAddress.isNull() &&
            this.context !== null &&
            typeof this.context.x0.toInt32 === "function" &&
            typeof this.context.d0 === "number" &&
            typeof this.errno === "number" &&
            typeof this.threadId === "number" &&
            this.threadId > 0 &&
            this.depth === 0;
        this.marker = "first-listener-state";
        args[0] = args[0].add(1);
    },
    onLeave(retval) {
        interceptorEvents.push("first-leave");
        interceptorState.sharedThisOk = this.marker === "first-listener-state";
        retval.replace(retval.toInt32() + 10);
    }
});

var secondListener = Interceptor.attach(nativeTarget, {
    onEnter(args) {
        interceptorEvents.push("second-enter");
        interceptorState.secondSawFirstArgChange = args[0].toInt32() === 3;
        this.marker = "second-listener-state";
    },
    onLeave(retval) {
        interceptorEvents.push("second-leave");
        interceptorState.secondSawFirstRetvalChange = retval.toInt32() === baseline33 + 10;
        retval.replace(retval.toInt32() + 20);
    }
});

assertEqual("Interceptor multi-listener result", nativeAdd(2, 3), baseline33 + 30);
assertEqual(
    "Interceptor listener order",
    interceptorEvents.join(","),
    "first-enter,second-enter,first-leave,second-leave"
);
assertTrue("Interceptor invocation metadata", interceptorState.metadataOk);
assertTrue("Interceptor listener this isolation", interceptorState.sharedThisOk);
assertTrue("Interceptor chained argument update", interceptorState.secondSawFirstArgChange);
assertTrue("Interceptor chained retval update", interceptorState.secondSawFirstRetvalChange);

assertEqual("Interceptor first detach return", firstListener.detach(), undefined);
interceptorEvents.length = 0;
assertEqual("Interceptor independent detach", nativeAdd(2, 3), baseline23 + 20);
assertEqual("Interceptor remaining listener", interceptorEvents.join(","), "second-enter,second-leave");
assertEqual("Interceptor idempotent detach", firstListener.detach(), undefined);
assertEqual("Interceptor second detach return", secondListener.detach(), undefined);
assertEqual("Interceptor last detach restores target", nativeAdd(2, 3), baseline23);

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
}

var periodicStalkerReceiveReady = false;
var periodicStalkerSummaryReady = false;
var periodicStalkerAnnounced = false;

function announceReadyAfterPeriodicStalker() {
    if (periodicStalkerAnnounced || !periodicStalkerReceiveReady || !periodicStalkerSummaryReady)
        return;
    periodicStalkerAnnounced = true;
    console.log("[smoke][READY] memory/native/java hooks installed");
}

function startPeriodicStalkerTest() {
    Stalker.follow(Process.id, {
        events: { call: true, ret: true },
        onReceive(events) {
            if (!periodicStalkerReceiveReady) {
                var rows = Stalker.parse(events, { annotate: true, stringify: true });
                assertTrue("Stalker periodic onReceive", rows.length > 0);
                periodicStalkerReceiveReady = true;
            }
            announceReadyAfterPeriodicStalker();
        },
        onCallSummary(summary) {
            if (!periodicStalkerSummaryReady) {
                assertTrue("Stalker periodic onCallSummary", summary !== null && typeof summary === "object");
                periodicStalkerSummaryReady = true;
            }
            announceReadyAfterPeriodicStalker();
        }
    });
}

Java.ready(function () {
    var Target = Java.use("com.example.rfhooktarget.HookTarget");
    var unloadInstance = Target.$new();
    var javaStringHookHits = 0;
    Target.javaStringLength.impl = function (value) {
        javaStringHookHits++;
        return this.$orig(value + "-hook");
    };
    assertEqual("Java explicit String orig", unloadInstance.javaStringLength("abc"), 8);
    assertEqual("Java wrapper invokes hook once", javaStringHookHits, 1);
    runNativeTests();
    var unloadHandle = unloadInstance.nativeOpenUnloadTarget();
    assertTrue("module unload test handle", unloadHandle !== 0 && unloadHandle !== 0n);
    var unloadTarget = Module.findExportByName("librfunloadtarget.so", "rf_unload_add");
    assertTrue("module unload test export", unloadTarget !== null);

    var unloadHits = 0;
    var unloadListener = Interceptor.attach(unloadTarget, {
        onEnter() {
            unloadHits++;
        },
        onLeave(retval) {
            retval.replace(retval.toInt32() + 40);
        }
    });
    assertEqual(
        "module unload hooked call",
        unloadInstance.nativeCallUnloadTarget(unloadHandle, 2, 3),
        545
    );
    assertEqual("module unload hook hit", unloadHits, 1);
    assertEqual("module unload close", unloadInstance.nativeCloseUnloadTarget(unloadHandle), 0);
    assertTrue("module unload mapping removed", Module.findByAddress(unloadTarget) === null);

    var staleAttachRejected = false;
    var staleListener = null;
    try {
        staleListener = Interceptor.attach(unloadTarget, { onEnter() {} });
    } catch (e) {
        staleAttachRejected = true;
    }
    if (staleListener !== null) {
        staleListener.detach();
    }
    assertTrue("module unload stale hook rejected", staleAttachRejected);
    assertEqual("module unload retired listener detach", unloadListener.detach(), undefined);

    var reloadHandle = unloadInstance.nativeOpenUnloadTarget();
    assertTrue("module reload test handle", reloadHandle !== 0 && reloadHandle !== 0n);
    var reloadTarget = Module.findExportByName("librfunloadtarget.so", "rf_unload_add");
    assertTrue("module reload test export", reloadTarget !== null);
    var reloadHits = 0;
    var reloadListener = Interceptor.attach(reloadTarget, {
        onEnter() {
            reloadHits++;
        },
        onLeave(retval) {
            retval.replace(retval.toInt32() + 60);
        }
    });
    assertEqual(
        "module reload hooked call",
        unloadInstance.nativeCallUnloadTarget(reloadHandle, 4, 5),
        569
    );
    assertEqual("module reload hook hit", reloadHits, 1);
    assertEqual("module reload listener detach", reloadListener.detach(), undefined);
    assertEqual("module reload close", unloadInstance.nativeCloseUnloadTarget(reloadHandle), 0);

    Target.javaCompute.impl = function (value) {
        var original = this.$orig(value);
        console.log("[smoke][java-hit] value=" + value + " original=" + original);
        return original + 1000;
    };
    startPeriodicStalkerTest();
});
