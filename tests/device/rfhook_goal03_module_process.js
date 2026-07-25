function pass(name, value) {
    console.log("[goal03][PASS] " + name + "=" + value);
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
    var address = Module.findExportByName("librf_goal03_control.so", name);
    if (address === null)
        address = Module.findGlobalExportByName(name);
    if (address === null)
        throw new Error("missing control export: " + name);
    return address;
}

var controlOpen = new NativeFunction(requireExport("rf_goal03_open"), "int", []);
var controlSymbol = new NativeFunction(requireExport("rf_goal03_symbol"), "pointer", []);
var controlClose = new NativeFunction(requireExport("rf_goal03_close"), "int", []);
var sleepMs = new NativeFunction(requireExport("rf_goal03_sleep_ms"), "void", ["uint"]);
var threadStart = new NativeFunction(requireExport("rf_goal03_thread_start"), "int", []);
var threadRename = new NativeFunction(requireExport("rf_goal03_thread_rename"), "int", []);
var threadStop = new NativeFunction(requireExport("rf_goal03_thread_stop"), "int", []);

var libc = Process.getModuleByName("libc.so");
assertTrue("Process module instance", libc instanceof Module);
assertTrue("Process.mainModule instance", Process.mainModule instanceof Module);
assertEqual("find module by address identity", Process.getModuleByAddress(libc.base).base, libc.base);
assertEqual("legacy/instance export", libc.findExportByName("open"), Module.findExportByName(libc.path, "open"));
assertEqual("global export", Module.findGlobalExportByName("open"), libc.findExportByName("open"));
assertTrue("module JSON", JSON.stringify(libc).indexOf(libc.path) !== -1);
assertTrue("module sections", libc.enumerateSections().length > 0);
assertTrue("module dependencies", libc.enumerateDependencies().length > 0);
assertTrue("module ranges", libc.enumerateRanges("r-x").length > 0);
assertTrue("module imports", libc.enumerateImports().length > 0);
assertTrue("module exports", libc.enumerateExports().length > 0);
assertTrue("module symbols", libc.enumerateSymbols().length > 0);
assertEqual("find symbol", libc.findSymbolByName("open"), libc.findExportByName("open"));
assertEqual("ensureInitialized", libc.ensureInitialized(), undefined);

var map = new ModuleMap();
assertTrue("ModuleMap has libc", map.has(libc.base));
assertEqual("ModuleMap find", map.find(libc.base).base, libc.base);
assertEqual("ModuleMap name", map.getName(libc.base), libc.name);
assertEqual("ModuleMap path", map.getPath(libc.base), libc.path);
assertTrue("ModuleMap values", map.values().every(function (module) { return module instanceof Module; }));
var filteredMap = new ModuleMap(function (module) { return module.path === libc.path; });
assertEqual("ModuleMap filter", filteredMap.values().length, 1);

var moduleEvents = [];
var moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
        if (module.name.indexOf("librf_goal03") !== -1 || module.path.indexOf("wwb_librf_goal03") !== -1)
            moduleEvents.push("add:" + module.path + ":" + module.base);
    },
    onRemoved(module) {
        if (module.name.indexOf("librf_goal03") !== -1 || module.path.indexOf("wwb_librf_goal03") !== -1)
            moduleEvents.push("remove:" + module.path + ":" + module.base);
    }
});

assertEqual("fixture open", controlOpen(), 0);
var fixtureAddress = controlSymbol();
assertTrue("fixture symbol", !fixtureAddress.isNull());
var fixture = Process.getModuleByAddress(fixtureAddress);
assertTrue("fixture instance", fixture instanceof Module);
assertEqual("fixture by full path", Process.getModuleByName("/data/local/tmp/librf_goal03_module.so").base, fixture.base);
assertEqual("fixture observer added once", moduleEvents.filter(function (event) {
    return event.indexOf("add:/data/local/tmp/librf_goal03_module.so:") === 0;
}).length, 1);
assertEqual("ModuleMap snapshot before update", map.find(fixtureAddress), null);
map.update();
assertEqual("ModuleMap after update", map.get(fixtureAddress).base, fixture.base);
assertEqual("fixture close", controlClose(), 0);
sleepMs(50);
assertEqual("fixture mapping gone", Process.findRangeByAddress(fixtureAddress), null);
assertEqual("fixture gone", Process.findModuleByAddress(fixtureAddress), null);
assertEqual("fixture observer removed once", moduleEvents.filter(function (event) {
    return event.indexOf("remove:/data/local/tmp/librf_goal03_module.so:") === 0;
}).length, 1);
assertEqual("ModuleMap stale snapshot", map.get(fixtureAddress).base, fixture.base);
map.update();
assertEqual("ModuleMap refreshed removal", map.find(fixtureAddress), null);

var sameA = Module.load("/data/local/tmp/rf-goal03-a/librf_goal03_same.so");
var sameB = Module.load("/data/local/tmp/rf-goal03-b/librf_goal03_same.so");
assertTrue("same-name distinct base", sameA.base.compare(sameB.base) !== 0);
assertEqual("same-name full path A", Process.getModuleByName(sameA.path).base, sameA.base);
assertEqual("same-name full path B", Process.getModuleByName(sameB.path).base, sameB.base);
assertEqual("same-name symbol A", new NativeFunction(sameA.getExportByName("rf_goal03_value"), "int", [])(), 3101);
assertEqual("same-name symbol B", new NativeFunction(sameB.getExportByName("rf_goal03_value"), "int", [])(), 3102);

var memfd = Module.load("/data/local/tmp/librf_goal03_memfd.so", true);
assertTrue("memfd instance", memfd instanceof Module);
assertTrue("memfd path", memfd.path.indexOf("wwb_librf_goal03_memfd.so") !== -1);
assertEqual("memfd address lookup", Process.getModuleByAddress(memfd.base).base, memfd.base);
assertEqual("memfd export", new NativeFunction(memfd.getExportByName("rf_goal03_value"), "int", [])(), 3303);
assertTrue("memfd dependencies", memfd.enumerateDependencies().length > 0);
assertEqual("memfd ensureInitialized", memfd.ensureInitialized(), undefined);

var hidden = Process.enumerateModules().filter(function (module) {
    return module.path.indexOf("wwb_so") !== -1;
})[0];
assertTrue("hidden agent module", hidden instanceof Module);
assertEqual("hidden address lookup", Process.getModuleByAddress(hidden.base).base, hidden.base);
assertEqual("hidden ensureInitialized fallback", hidden.ensureInitialized(), undefined);

assertEqual("same A observer added once", moduleEvents.filter(function (event) {
    return event.indexOf("add:" + sameA.path + ":") === 0;
}).length, 1);
assertEqual("same B observer added once", moduleEvents.filter(function (event) {
    return event.indexOf("add:" + sameB.path + ":") === 0;
}).length, 1);
assertEqual("memfd observer added once", moduleEvents.filter(function (event) {
    return event === "add:" + memfd.path + ":" + memfd.base;
}).length, 1);

var threadInitial = 0;
var threadAdded = 0;
var threadRemoved = 0;
var threadRenamed = 0;
var observedThreadId = 0;
var addedThreadIds = Object.create(null);
var threadObserver = Process.attachThreadObserver({
    onAdded(thread) {
        threadInitial++;
        addedThreadIds[String(thread.id)] = true;
    },
    onRemoved(thread) {
        if (thread.id === observedThreadId)
            threadRemoved++;
    },
    onRenamed(thread, previousName) {
        if (thread.name === "goal03-control") {
            observedThreadId = thread.id;
            threadAdded = addedThreadIds[String(thread.id)] ? 1 : 0;
        } else if (thread.id === observedThreadId && thread.name === "rf-g03-renamed" && previousName === "goal03-control") {
            threadRenamed++;
        }
    }
});
assertTrue("thread observer initial snapshot", threadInitial > 0);
assertEqual("thread start", threadStart(), 0);
sleepMs(50);
assertEqual("thread observer added once", threadAdded, 1);
assertEqual("thread rename", threadRename(), 0);
sleepMs(50);
assertEqual("thread observer renamed once", threadRenamed, 1);
assertEqual("thread stop", threadStop(), 0);
sleepMs(50);
assertEqual("thread observer removed once", threadRemoved, 1);
assertTrue("thread observer shape", Process.enumerateThreads().every(function (thread) {
    return typeof thread.id === "number" && typeof thread.state === "string";
}));
threadObserver.detach();
assertEqual("thread observer detach idempotent", threadObserver.detach(), undefined);

moduleObserver.detach();
var eventsBeforeDetach = moduleEvents.length;
assertEqual("fixture reopen after detach", controlOpen(), 0);
assertEqual("fixture reclose after detach", controlClose(), 0);
assertEqual("module observer detached", moduleEvents.length, eventsBeforeDetach);
assertEqual("module observer detach idempotent", moduleObserver.detach(), undefined);

Process.attachModuleObserver({
    onAdded(module) {
        if (module.path === "/data/local/tmp/librf_goal03_module.so")
            console.log("[goal03][STALE-CALLBACK] module added");
    },
    onRemoved(module) {
        if (module.path === "/data/local/tmp/librf_goal03_module.so")
            console.log("[goal03][STALE-CALLBACK] module removed");
    }
});
Process.attachThreadObserver({
    onAdded(thread) {
        if (thread.name === "goal03-control")
            console.log("[goal03][STALE-CALLBACK] thread added");
    },
    onRemoved(thread) {
        if (thread.name === "goal03-control" || thread.name === "rf-g03-renamed")
            console.log("[goal03][STALE-CALLBACK] thread removed");
    },
    onRenamed(thread) {
        if (thread.name === "rf-g03-renamed")
            console.log("[goal03][STALE-CALLBACK] thread renamed");
    }
});

console.log("[goal03][READY] module/process verified events=" + moduleEvents.length + " threads=" + threadInitial +
    " added=" + threadAdded + " renamed=" + threadRenamed + " removed=" + threadRemoved);
