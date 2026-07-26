// Goal 08: the Frida-compatible Java facade.
//
// Platform classes carry most of the checks so the test does not depend on the
// target app's internals; the app is only needed for a live ART runtime.

function pass(name, value) {
    console.log("[goal08][PASS] " + name + "=" + value);
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

// ------------------------------------------------------- before perform ----

// available/androidVersion must answer before the class loader is ready: a
// script asks them precisely to decide whether to touch Java at all.
assertEqual("Java.available is a boolean", typeof Java.available, "boolean");
assertTrue("Java.available is true in an app process", Java.available);
assertEqual("Java.androidVersion is a string", typeof Java.androidVersion, "string");
assertTrue("Java.androidVersion is non-empty", Java.androidVersion.length > 0);
assertEqual("Java.isMainThread is a function", typeof Java.isMainThread, "function");
assertEqual("Java.isMainThread returns a boolean", typeof Java.isMainThread(), "boolean");

for (const name of ["perform", "performNow", "cast", "retain", "array", "synchronized",
                    "enumerateLoadedClasses", "enumerateLoadedClassesSync"]) {
    assertEqual("Java." + name + " is a function", typeof Java[name], "function");
}

// Modifier values, as java.lang.reflect.Modifier defines them.
assertEqual("ACC_PUBLIC", Java.ACC_PUBLIC, 1);
assertEqual("ACC_STATIC", Java.ACC_STATIC, 8);
assertEqual("ACC_NATIVE", Java.ACC_NATIVE, 256);
assertEqual("ACC_SYNTHETIC", Java.ACC_SYNTHETIC, 4096);

assertThrows("perform rejects a non-function", function () { Java.perform(42); });
assertThrows("performNow rejects a non-function", function () { Java.performNow(42); });

// The project's own entry points must survive the compatibility layer.
assertEqual("Java.ready is still a function", typeof Java.ready, "function");
assertEqual("Java.use is still a function", typeof Java.use, "function");
assertEqual("Java.choose is still a function", typeof Java.choose, "function");

Java.perform(function () {
    try {
        runJavaChecks();
        console.log("[goal08][READY] Java facade verified");
    } catch (error) {
        console.log("[goal08][FAIL] " + (error && error.message ? error.message : error));
        throw error;
    }
});

function runJavaChecks() {
    // performNow runs synchronously, which is the whole difference from perform.
    var ranNow = false;
    Java.performNow(function () { ranNow = true; });
    assertTrue("performNow ran synchronously", ranNow);

    // ------------------------------------------------- loaded classes ----

    // Enumeration goes through JVMTI, which the agent will not late-load unless
    // RF_JAVA_CHOOSE_JVMTI_LATE_LOAD is set in the target's environment. That
    // default is deliberate, so the check adapts rather than forcing it: when
    // the plugin is unavailable the API must still fail in a way that tells the
    // caller what to do.
    var loaded = null;
    try {
        loaded = Java.enumerateLoadedClassesSync();
    } catch (error) {
        assertTrue(
            "enumerateLoadedClasses explains the JVMTI requirement",
            error.message.indexOf("JVMTI") !== -1
        );
    }

    if (loaded !== null) {
        assertTrue("enumerateLoadedClassesSync returned an array", Array.isArray(loaded));
        assertTrue("loaded classes are plentiful", loaded.length > 100);
        assertTrue("loaded classes include java.lang.String", loaded.indexOf("java.lang.String") !== -1);
        assertTrue(
            "class names use dots, not slashes",
            loaded.every(function (name) { return name.indexOf("/") === -1; })
        );

        var streamed = [];
        var completed = false;
        Java.enumerateLoadedClasses({
            onMatch(name) {
                streamed.push(name);
                return streamed.length === 5 ? "stop" : undefined;
            },
            onComplete() { completed = true; }
        });
        assertEqual("enumerateLoadedClasses honoured stop", streamed.length, 5);
        assertTrue("enumerateLoadedClasses called onComplete", completed);
    }

    // Class loader enumeration does not need JVMTI and must always work.
    var loaders = Java.enumerateClassLoadersSync();
    assertTrue("enumerateClassLoadersSync returned an array", Array.isArray(loaders));
    assertTrue("the process has at least one class loader", loaders.length > 0);

    // ------------------------------------------------------------ cast ----

    var StringClass = Java.use("java.lang.String");
    var text = StringClass.$new("goal08");
    assertEqual("constructed a java.lang.String", text.toString(), "goal08");

    var asObject = Java.cast(text, "java.lang.Object");
    assertEqual("cast keeps the identity", asObject.toString(), "goal08");
    assertEqual("cast reports the requested class", asObject.__jclass, "java.lang.Object");

    var ObjectClass = Java.use("java.lang.Object");
    var viaWrapper = Java.cast(text, ObjectClass);
    assertEqual("cast accepts a class wrapper", viaWrapper.__jclass, "java.lang.Object");

    assertThrows("cast rejects an unrelated class", function () {
        return Java.cast(text, "java.lang.Integer");
    });
    assertThrows("cast rejects a dead handle", function () {
        return Java.cast({ __jptr: 0, __jclass: "java.lang.Object" }, "java.lang.Object");
    });

    // ---------------------------------------------------------- retain ----

    var retained = Java.retain(text);
    assertEqual("retained object still reads", retained.toString(), "goal08");
    assertEqual("retained object is marked global", retained.__jglobal, true);
    assertEqual("retain exposes $dispose", typeof retained.$dispose, "function");
    retained.$dispose();
    // Disposing twice must stay a no-op: scripts release in finally blocks that
    // can run after an earlier dispose.
    retained.$dispose();
    pass("retain tolerates a second dispose", true);

    assertThrows("retain rejects a dead handle", function () {
        return Java.retain({ __jptr: 0, __jclass: "java.lang.Object" });
    });

    // ----------------------------------------------------------- array ----

    // Contents are checked by handing the array to real Java code rather than
    // by reading it back through the internal accessor: that is what a script
    // builds an array for, and it exercises the JNI argument path too.
    var Arrays = Java.use("java.util.Arrays");

    var ints = Java.array("int", [1, 2, 3, 4]);
    assertEqual("int array has the right class", ints.__jclass, "[I");
    assertEqual("int array reaches Java intact", Arrays.toString("([I)Ljava/lang/String;", ints), "[1, 2, 3, 4]");

    var bytes = Java.array("byte", [65, 66]);
    assertEqual("byte array has the right class", bytes.__jclass, "[B");
    assertEqual("byte array reaches Java intact", Arrays.toString("([B)Ljava/lang/String;", bytes), "[65, 66]");

    var doubles = Java.array("double", [1.5, 2.5]);
    assertEqual("double array has the right class", doubles.__jclass, "[D");
    assertEqual(
        "double array reaches Java intact",
        Arrays.toString("([D)Ljava/lang/String;", doubles),
        "[1.5, 2.5]"
    );

    var booleans = Java.array("boolean", [true, false]);
    assertEqual(
        "boolean array reaches Java intact",
        Arrays.toString("([Z)Ljava/lang/String;", booleans),
        "[true, false]"
    );

    var longs = Java.array("long", [10, 20]);
    assertEqual("long array reaches Java intact", Arrays.toString("([J)Ljava/lang/String;", longs), "[10, 20]");

    var empty = Java.array("int", []);
    assertEqual("empty array reaches Java intact", Arrays.toString("([I)Ljava/lang/String;", empty), "[]");

    var strings = Java.array("java.lang.String", [text, null]);
    assertEqual("object array has the right class", strings.__jclass, "[Ljava.lang.String;");
    assertEqual(
        "object array reaches Java intact",
        Arrays.toString("([Ljava/lang/Object;)Ljava/lang/String;", strings),
        "[goal08, null]"
    );

    // Reading elements back must dispatch on the element type: routing a
    // primitive array through GetObjectArrayElement is a JNI error that aborts
    // the runtime, which is what used to happen here.
    assertEqual("int array reads back through the index", ints[0], 1);
    assertEqual("int array reads its last element", ints[3], 4);
    assertEqual("byte array keeps the sign", Java.array("byte", [-1])[0], -1);
    assertEqual("boolean array reads back", booleans[0], true);
    assertEqual("double array reads back", doubles[1], 2.5);
    assertEqual("long array reads back", longs[0], 10);
    assertEqual("short array reads back", Java.array("short", [-300])[0], -300);
    assertEqual("char array reads back", Java.array("char", [20320])[0], 20320);
    assertEqual("float array reads back", Java.array("float", [0.5])[0], 0.5);
    assertEqual("object array reads back", strings[0].toString(), "goal08");
    assertEqual("object array keeps null", strings[1], null);

    assertThrows("array rejects a non-array", function () { return Java.array("int", 5); });
    assertThrows("array rejects an unknown class", function () {
        return Java.array("no.such.Class", []);
    });

    // ---------------------------------------------------- synchronized ----

    var insideLock = false;
    Java.synchronized(text, function () { insideLock = true; });
    assertTrue("synchronized ran the body", insideLock);

    // The monitor must be released even when the body throws, or the next
    // acquire on this object would hang.
    assertThrows("synchronized propagates body errors", function () {
        Java.synchronized(text, function () { throw new Error("boom"); });
    });
    var reacquired = false;
    Java.synchronized(text, function () { reacquired = true; });
    assertTrue("synchronized re-acquired after a throw", reacquired);

    assertThrows("synchronized rejects a dead handle", function () {
        Java.synchronized({ __jptr: 0 }, function () {});
    });
}
