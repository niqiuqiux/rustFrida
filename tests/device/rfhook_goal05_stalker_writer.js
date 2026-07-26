// Goal 05: ARM64 writer/relocator on the Stalker transform iterator, plus the
// drop and retirement counters exposed by Stalker.statistics().
//
// Everything follows the current thread and drives the target synchronously,
// which is how the other Stalker regressions avoid starving transform callbacks
// of the JavaScript engine.

function pass(name, value) {
    console.log("[goal05][PASS] " + name + "=" + value);
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
    var address = Module.findExportByName("librf_goal05_stalker_writer.so", name);
    if (address === null)
        address = Module.findExportByName(null, name);
    if (address === null)
        throw new Error("missing Goal 05 export: " + name);
    return address;
}

var runBatch = new NativeFunction(requireExport("rf_goal05_run_batch"), "int", ["int"]);
var churn = new NativeFunction(requireExport("rf_goal05_churn"), "int", ["int"]);
var computeSize = new NativeFunction(requireExport("rf_goal05_compute_size"), "uint64", []);
var computeStart = requireExport("rf_goal05_compute");
// The transform only rewrites instructions inside this window; the reference
// implementation next to it must keep running untouched.
var computeEnd = computeStart.add(computeSize());

// ---------------------------------------------------------------- surface ---

assertEqual("Arm64Relocator is a constructor", typeof Arm64Relocator, "function");
assertEqual("Stalker.statistics is a function", typeof Stalker.statistics, "function");

var baseline = Stalker.statistics();
assertEqual("statistics reports no active traces", baseline.activeTraces, 0);
assertEqual("statistics starts with no drops", baseline.droppedEvents, 0);
assertTrue("statistics reports a trace array", Array.isArray(baseline.traces));

var baselineMismatches = runBatch(64);
assertEqual("fixture agrees with itself before tracing", baselineMismatches, 0);

// ------------------------------------------------------------- transform ----

var CONTROL_FLOW = /^(b|bl|br|blr|braa|brab|blraa|blrab|ret|retaa|retab|cbz|cbnz|tbz|tbnz)$/;

function isControlFlow(mnemonic) {
    return CONTROL_FLOW.test(mnemonic) || mnemonic.indexOf("b.") === 0;
}

// Written by the emitted code only if the branch fell through, which would mean
// putBLabel()/putLabel() did not resolve to the same place.
var branchGuard = Memory.alloc(8);
branchGuard.writeU64(0);

var capturedIterator = null;
var relocatedInstructions = 0;
var guardedBlocks = 0;
var calloutHits = 0;
var writerProbe = null;
var relocatorProbe = null;
var transformError = null;

function emitGuardedBranch(iterator) {
    // x16/x17 are scratch here, and the push/pop pair guarantees the original
    // function sees them unchanged whichever path runs.
    iterator.putPushRegReg("x16", "x17");
    iterator.putBLabel("rf-goal05-skip");
    iterator.putLdrRegU64("x16", branchGuard.toString());
    iterator.putLdrRegU64("x17", 1);
    iterator.putStrRegRegOffset("x17", "x16", 0);
    iterator.putLabel("rf-goal05-skip");
    iterator.putPopRegReg("x16", "x17");
}

function probeWriterSurface(iterator) {
    var probe = {};
    probe.pcIsPointer = iterator.pc instanceof NativePointer;
    probe.codeIsPointer = iterator.code instanceof NativePointer;
    probe.baseIsPointer = iterator.base instanceof NativePointer;
    probe.offsetIsNumber = typeof iterator.offset === "number";
    probe.memoryAccess = iterator.memoryAccess;
    probe.signIsPointer = iterator.sign(iterator.pc) instanceof NativePointer;
    probe.canBranchToSelf = iterator.canBranchDirectlyBetween(iterator.pc, iterator.pc);
    try {
        iterator.putMovRegReg("x0", "not-a-register");
        probe.rejectsUnknownRegister = false;
    } catch (error) {
        probe.rejectsUnknownRegister = true;
    }
    try {
        iterator.putBCondLabel("nope", "rf-goal05-skip");
        probe.rejectsUnknownCondition = false;
    } catch (error) {
        probe.rejectsUnknownCondition = true;
    }
    return probe;
}

function probeRelocatorLifecycle(address, iterator) {
    var probe = {};
    var relocator = new Arm64Relocator(address, iterator);
    probe.inputIsPointer = relocator.input instanceof NativePointer;
    probe.eoiIsBoolean = typeof relocator.eoi === "boolean";
    probe.eobIsBoolean = typeof relocator.eob === "boolean";
    relocator.dispose();
    try {
        relocator.readOne();
        probe.rejectsUseAfterDispose = false;
    } catch (error) {
        probe.rejectsUseAfterDispose = true;
    }
    // A second dispose() must stay a no-op rather than double-freeing.
    relocator.dispose();
    probe.toleratesDoubleDispose = true;
    return probe;
}

function onCallout() {
    calloutHits++;
}

function transform(iterator) {
    var instruction;
    var emittedGuard = false;
    var relocated = false;
    while ((instruction = iterator.next()) !== null) {
        var inCompute =
            instruction.address.compare(computeStart) >= 0 && instruction.address.compare(computeEnd) < 0;
        // Record failures instead of propagating them: an exception here makes
        // Gum keep the rest of the block, which would silently hide the bug.
        var emitted = false;
        try {
            if (inCompute && capturedIterator === null) {
                capturedIterator = iterator;
                writerProbe = probeWriterSurface(iterator);
                relocatorProbe = probeRelocatorLifecycle(instruction.address, iterator);
            }

            if (inCompute && !emittedGuard) {
                emittedGuard = true;
                guardedBlocks++;
                emitGuardedBranch(iterator);
                iterator.putCallout(onCallout);
            }

            if (inCompute && !relocated && !isControlFlow(instruction.mnemonic)) {
                // Emit this instruction ourselves instead of keep(): the
                // relocator is what makes that safe for PC-relative encodings.
                relocated = true;
                relocatedInstructions++;
                var relocator = new Arm64Relocator(instruction.address, iterator);
                relocator.readOne();
                relocator.writeOne();
                relocator.dispose();
                emitted = true;
            }
        } catch (error) {
            if (transformError === null)
                transformError = String(error);
        }

        if (!emitted)
            iterator.keep();
    }
}

var threadId = Process.getCurrentThreadId();

Stalker.follow(threadId, {
    events: { call: true, ret: true },
    transform: transform
});

var tracedMismatches = runBatch(64);
var tracedStats = Stalker.statistics();

Stalker.unfollow(threadId);
Stalker.flush();

if (transformError !== null)
    throw new Error("transform reported an error: " + transformError);
pass("transform ran without errors", true);
assertEqual("rewritten function kept its semantics", tracedMismatches, 0);
assertTrue("transform emitted a guarded branch", guardedBlocks > 0);
assertTrue("transform re-emitted an instruction via the relocator", relocatedInstructions > 0);
assertTrue("callout fired from generated code", calloutHits > 0);
assertEqual("emitted branch was taken", branchGuard.readU64(), 0);
assertEqual("statistics counted the followed thread", tracedStats.activeTraces, 1);
assertEqual("statistics reported the followed tid", tracedStats.traces[0].threadId, threadId);

assertTrue("writer probe ran", writerProbe !== null);
assertTrue("writer exposes pc as a pointer", writerProbe.pcIsPointer);
assertTrue("writer exposes code as a pointer", writerProbe.codeIsPointer);
assertTrue("writer exposes base as a pointer", writerProbe.baseIsPointer);
assertTrue("writer exposes offset as a number", writerProbe.offsetIsNumber);
assertTrue("writer sign() returns a pointer", writerProbe.signIsPointer);
assertEqual("writer canBranchDirectlyBetween works", writerProbe.canBranchToSelf, true);
assertTrue("writer rejects unknown register names", writerProbe.rejectsUnknownRegister);
assertTrue("writer rejects unknown condition codes", writerProbe.rejectsUnknownCondition);
assertEqual("iterator reports memory access", writerProbe.memoryAccess, "open");

assertTrue("relocator probe ran", relocatorProbe !== null);
assertTrue("relocator exposes input as a pointer", relocatorProbe.inputIsPointer);
assertTrue("relocator exposes eoi as a boolean", relocatorProbe.eoiIsBoolean);
assertTrue("relocator exposes eob as a boolean", relocatorProbe.eobIsBoolean);
assertTrue("relocator rejects use after dispose", relocatorProbe.rejectsUseAfterDispose);
assertTrue("relocator tolerates a second dispose", relocatorProbe.toleratesDoubleDispose);

// The iterator survives the callback as a JavaScript object, but every writer
// member must refuse to touch the retired Gum writer behind it.
assertThrows("iterator.putNop() after the callback", function () {
    capturedIterator.putNop();
});
assertThrows("iterator.pc after the callback", function () {
    return capturedIterator.pc;
});
assertThrows("iterator.keep() after the callback", function () {
    capturedIterator.keep();
});
assertThrows("new Arm64Relocator() outside a transform", function () {
    return new Arm64Relocator(computeStart, capturedIterator);
});

var unfollowedStats = Stalker.statistics();
assertEqual("statistics drops the trace after unfollow", unfollowedStats.activeTraces, 0);
assertEqual("untraced code still agrees", runBatch(32), 0);

// ------------------------------------------------------- dropped events -----

// A one-slot queue cannot hold a batch, so the sink must discard events instead
// of growing, and the discard must be visible.
Stalker.queueCapacity = 1;
Stalker.queueDrainInterval = 0;
Stalker.follow(threadId, { events: { call: true, ret: true } });
var churnResult = churn(96);
var dropStats = Stalker.statistics();
Stalker.unfollow(threadId);
Stalker.flush();

assertTrue("churn ran under a full queue", typeof churnResult === "number");
assertTrue("queue-full events are counted", dropStats.droppedEvents > 0);
assertTrue("per-thread drops are reported", dropStats.traces[0].droppedEvents > 0);
assertTrue(
    "queued events never exceed the configured capacity",
    dropStats.traces[0].queuedEvents <= dropStats.traces[0].queueCapacity
);
assertEqual("a full queue did not corrupt results", runBatch(32), 0);

var retainedStats = Stalker.statistics();
assertTrue("drop counts survive unfollow", retainedStats.droppedEvents >= dropStats.droppedEvents);

Stalker.queueCapacity = 16384;
Stalker.queueDrainInterval = 250;
for (var round = 0; round !== 4; round++)
    Stalker.garbageCollect();

var finalStats = Stalker.statistics();
assertEqual("no traces remain", finalStats.activeTraces, 0);
assertEqual("no call probes remain", finalStats.activeCallProbes, 0);
assertEqual("no probe anchors remain", finalStats.callProbeAnchors, 0);

console.log("[goal05][READY] Stalker ARM64 writer verified");

// -------------------------------------------- concurrent background work ----
//
// The Stalker drain worker and the timer pump are two agent-created threads.
// The pthread shim clones without CLONE_SETTLS, so every thread it makes shares
// one TLS block; two concurrent Memory.scan() calls were enough to crash the
// target when that was found (roadmap §7.1). Every regression so far has
// exercised one background thread at a time, so nothing covered the combination
// the agent actually ships. This runs both at once and makes each one prove it
// got work done.

var concurrentTicks = 0;
var concurrentBytes = 0;
var churnRounds = 0;

Stalker.queueCapacity = 16384;
Stalker.queueDrainInterval = 10;

var tickTimer = setInterval(function () { concurrentTicks++; }, 5);

Stalker.follow(threadId, {
    events: { call: true, ret: true },
    onReceive: function (events) { concurrentBytes += events.byteLength; }
});

// Churn from a timer rather than a loop: a synchronous loop would hold the
// engine throughout, and the point is to have both threads entering it.
var churnTimer = setInterval(function () {
    churn(64);
    if (++churnRounds !== 20)
        return;

    clearInterval(churnTimer);
    clearInterval(tickTimer);
    Stalker.unfollow(threadId);
    Stalker.flush();

    setTimeout(function () {
        try {
            assertTrue("timers ran while Stalker was following", concurrentTicks > 10);
            assertTrue("Stalker delivered events while timers ran", concurrentBytes > 0);
            assertEqual("churn completed every round", churnRounds, 20);
            for (var round = 0; round !== 4; round++)
                Stalker.garbageCollect();
            assertEqual("no traces remain after concurrent use", Stalker.statistics().activeTraces, 0);
            console.log("[goal05][CONCURRENT-READY] drain worker and timer pump coexisted");
        } catch (error) {
            console.log("[goal05][FAIL] " + (error && error.message ? error.message : error));
        }
    }, 250);
}, 10);
