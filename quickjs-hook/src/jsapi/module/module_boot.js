(function () {
    "use strict";

    const rawModule = globalThis.Module;
    const rawProcess = globalThis.Process;

    function Module(details) {
        if (!(this instanceof Module))
            return new Module(details);
        if (details === null || typeof details !== "object")
            throw new TypeError("Module details must be an object");

        this.name = details.name;
        this.version = details.version === undefined ? null : details.version;
        this.path = details.path;
        this.base = details.base;
        this.size = details.size;
    }

    function wrapModule(details) {
        if (details === null || details === undefined || details instanceof Module)
            return details;
        return new Module(details);
    }

    function requiredAddress(address, message) {
        if (address === null)
            throw new Error(message);
        return address;
    }

    Object.defineProperties(Module.prototype, {
        ensureInitialized: {
            enumerable: true,
            value() { return rawModule.__ensureInitialized(this); }
        },
        enumerateImports: {
            enumerable: true,
            value() { return rawModule.enumerateImports(this.path); }
        },
        enumerateExports: {
            enumerable: true,
            value() { return rawModule.enumerateExports(this.path); }
        },
        enumerateSymbols: {
            enumerable: true,
            value() { return rawModule.enumerateSymbols(this.path); }
        },
        enumerateRanges: {
            enumerable: true,
            value(protection) { return rawModule.enumerateRanges(this.path, protection); }
        },
        enumerateSections: {
            enumerable: true,
            value() { return rawModule.__enumerateSections(this); }
        },
        enumerateDependencies: {
            enumerable: true,
            value() { return rawModule.__enumerateDependencies(this); }
        },
        findExportByName: {
            enumerable: true,
            value(symbolName) { return rawModule.findExportByName(this.path, symbolName); }
        },
        getExportByName: {
            enumerable: true,
            value(symbolName) {
                return requiredAddress(this.findExportByName(symbolName),
                    `${this.path}: unable to find export '${symbolName}'`);
            }
        },
        findSymbolByName: {
            enumerable: true,
            value(symbolName) { return rawModule.__findSymbolByName(this, symbolName); }
        },
        getSymbolByName: {
            enumerable: true,
            value(symbolName) {
                return requiredAddress(this.findSymbolByName(symbolName),
                    `${this.path}: unable to find symbol '${symbolName}'`);
            }
        },
        toJSON: {
            enumerable: true,
            value() {
                const { name, version, base, size, path } = this;
                return { name, version, base, size, path };
            }
        }
    });

    const copyStatic = [
        "findExportByName", "findBaseAddress", "findByAddress", "enumerateModules",
        "enumerateExports", "enumerateImports", "enumerateSymbols", "enumerateRanges"
    ];
    for (const name of copyStatic) {
        Object.defineProperty(Module, name, {
            enumerable: true,
            value: name === "findByAddress"
                ? function (address) { return wrapModule(rawModule.findByAddress(address)); }
                : name === "enumerateModules"
                    ? function () { return rawModule.enumerateModules().map(wrapModule); }
                    : rawModule[name].bind(rawModule)
        });
    }
    Object.defineProperties(Module, {
        load: {
            enumerable: true,
            value() {
                const module = rawModule.load.apply(rawModule, arguments);
                rawProcess.__dispatchObserverEvents();
                return wrapModule(module);
            }
        },
        findGlobalExportByName: {
            enumerable: true,
            value(symbolName) { return rawModule.findExportByName(null, symbolName); }
        },
        getGlobalExportByName: {
            enumerable: true,
            value(symbolName) {
                return requiredAddress(Module.findGlobalExportByName(symbolName),
                    `unable to find global export '${symbolName}'`);
            }
        }
    });

    const rawEnumerateModules = rawProcess.enumerateModules.bind(rawProcess);
    const rawFindModuleByName = rawProcess.findModuleByName.bind(rawProcess);
    const rawFindModuleByAddress = rawProcess.findModuleByAddress.bind(rawProcess);
    rawProcess.enumerateModules = function () { return rawEnumerateModules().map(wrapModule); };
    rawProcess.findModuleByName = function (name) { return wrapModule(rawFindModuleByName(name)); };
    rawProcess.findModuleByAddress = function (address) { return wrapModule(rawFindModuleByAddress(address)); };
    rawProcess.getModuleByName = function (name) {
        const module = rawProcess.findModuleByName(name);
        if (module === null)
            throw new Error(`unable to find module '${name}'`);
        return module;
    };
    rawProcess.getModuleByAddress = function (address) {
        const module = rawProcess.findModuleByAddress(address);
        if (module === null)
            throw new Error(`unable to find module containing ${address}`);
        return module;
    };
    rawProcess.mainModule = wrapModule(rawProcess.mainModule);

    function makeObserver(attach, detach, callbacks) {
        const id = attach(callbacks);
        let attached = true;
        return {
            detach() {
                if (!attached)
                    return;
                attached = false;
                detach(id);
            }
        };
    }

    const rawAttachModuleObserver = rawProcess.__attachModuleObserver.bind(rawProcess);
    const rawDetachModuleObserver = rawProcess.__detachModuleObserver.bind(rawProcess);
    const rawAttachThreadObserver = rawProcess.__attachThreadObserver.bind(rawProcess);
    const rawDetachThreadObserver = rawProcess.__detachThreadObserver.bind(rawProcess);
    rawProcess.attachModuleObserver = function (callbacks) {
        return makeObserver(rawAttachModuleObserver, rawDetachModuleObserver, callbacks);
    };
    rawProcess.attachThreadObserver = function (callbacks) {
        return makeObserver(rawAttachThreadObserver, rawDetachThreadObserver, callbacks);
    };

    function ModuleMap(filter) {
        if (!(this instanceof ModuleMap))
            return new ModuleMap(filter);
        if (filter !== undefined && typeof filter !== "function")
            throw new TypeError("ModuleMap filter must be a function");
        this._filter = filter || null;
        this._values = [];
        this.update();
    }

    Object.defineProperties(ModuleMap.prototype, {
        has: {
            enumerable: true,
            value(address) { return this.find(address) !== null; }
        },
        find: {
            enumerable: true,
            value(address) {
                const needle = ptr(address);
                for (const module of this._values) {
                    if (needle.compare(module.base) >= 0 && needle.compare(module.base.add(module.size)) < 0)
                        return module;
                }
                return null;
            }
        },
        get: {
            enumerable: true,
            value(address) {
                const module = this.find(address);
                if (module === null)
                    throw new Error(`unable to find module containing ${address}`);
                return module;
            }
        },
        findName: {
            enumerable: true,
            value(address) { const module = this.find(address); return module === null ? null : module.name; }
        },
        getName: {
            enumerable: true,
            value(address) { const module = this.get(address); return module.name; }
        },
        findPath: {
            enumerable: true,
            value(address) { const module = this.find(address); return module === null ? null : module.path; }
        },
        getPath: {
            enumerable: true,
            value(address) { const module = this.get(address); return module.path; }
        },
        update: {
            enumerable: true,
            value() {
                const modules = rawProcess.enumerateModules();
                this._values = this._filter === null ? modules : modules.filter(this._filter);
            }
        },
        values: {
            enumerable: true,
            value() { return this._values.slice(); }
        }
    });

    Object.defineProperty(globalThis, "Module", { configurable: true, writable: true, value: Module });
    Object.defineProperty(globalThis, "ModuleMap", { configurable: true, writable: true, value: ModuleMap });
    Object.defineProperty(globalThis, "__rf_module_wrap", { configurable: true, value: wrapModule });
})();
