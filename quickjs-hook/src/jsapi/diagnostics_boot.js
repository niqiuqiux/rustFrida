(function () {
    "use strict";

    const native = {
        symbolFromAddress: globalThis.__rf_debug_symbol_from_address,
        symbolFromName: globalThis.__rf_debug_symbol_from_name,
        getFunctionByName: globalThis.__rf_debug_symbol_get_function_by_name,
        findFunctionsNamed: globalThis.__rf_debug_symbol_find_functions_named,
        findFunctionsMatching: globalThis.__rf_debug_symbol_find_functions_matching,
        loadSymbols: globalThis.__rf_debug_symbol_load,
        backtrace: globalThis.__rf_thread_backtrace,
        parseInstruction: globalThis.__rf_instruction_parse,
        enumerateModuleApiMatches: globalThis.__rf_api_resolver_enumerate_matches
    };

    class DebugSymbol {
        constructor() {
            throw new Error("not user-instantiable");
        }

        static fromAddress(address) { return makeDebugSymbol(native.symbolFromAddress(address)); }
        static fromName(name) { return makeDebugSymbol(native.symbolFromName(name)); }
        static getFunctionByName(name) { return native.getFunctionByName(name); }
        static findFunctionsNamed(name) { return native.findFunctionsNamed(name); }
        static findFunctionsMatching(pattern) { return native.findFunctionsMatching(pattern); }
        static load(path) { return native.loadSymbols(path); }

        toString() {
            if (this.name === null)
                return this.address.isNull() ? "0" : this.address.toString();
            let result = this.address.toString() + " " + this.moduleName + "!" + this.name;
            if (this.fileName !== null && this.fileName.length !== 0) {
                result += " " + this.fileName + ":" + this.lineNumber;
                if (this.column !== 0)
                    result += ":" + this.column;
            }
            return result;
        }

        toJSON() {
            return {
                address: this.address,
                name: this.name,
                moduleName: this.moduleName,
                fileName: this.fileName,
                lineNumber: this.lineNumber,
                column: this.column
            };
        }
    }

    function makeDebugSymbol(details) {
        return Object.assign(Object.create(DebugSymbol.prototype), details);
    }

    const Backtracer = Object.freeze({ ACCURATE: 1, FUZZY: 2 });
    const Thread = Object.create(null);
    Object.defineProperty(Thread, "backtrace", {
        configurable: true,
        enumerable: true,
        value(cpuContext = null, backtracerOrOptions = {}) {
            const options = typeof backtracerOrOptions === "object"
                ? backtracerOrOptions
                : { backtracer: backtracerOrOptions };
            const { backtracer = Backtracer.ACCURATE, limit = 0 } = options;
            return native.backtrace(cpuContext, backtracer, limit);
        }
    });

    class Instruction {
        constructor() {
            throw new Error("not user-instantiable");
        }

        static parse(address) {
            const details = native.parseInstruction(address);
            for (const operand of details.operands) {
                if (operand.type === "imm" || operand.type === "cimm")
                    operand.value = new Int64(operand.value);
            }
            return Object.assign(Object.create(Instruction.prototype), details);
        }

        toString() {
            return this.opStr.length === 0 ? this.mnemonic : this.mnemonic + " " + this.opStr;
        }

        toJSON() {
            return {
                address: this.address,
                next: this.next,
                size: this.size,
                mnemonic: this.mnemonic,
                opStr: this.opStr,
                operands: this.operands,
                regsAccessed: this.regsAccessed,
                regsRead: this.regsRead,
                regsWritten: this.regsWritten,
                groups: this.groups
            };
        }
    }

    class ApiResolver {
        constructor(type) {
            if (typeof type !== "string")
                throw new TypeError("ApiResolver type must be a string");
            if (type !== "module")
                throw new Error("ApiResolver type '" + type + "' is not available; only 'module' is supported");
        }

        enumerateMatches(query) {
            return native.enumerateModuleApiMatches(query);
        }
    }

    Object.defineProperties(globalThis, {
        DebugSymbol: { configurable: true, enumerable: true, writable: true, value: DebugSymbol },
        Backtracer: { configurable: true, enumerable: true, writable: true, value: Backtracer },
        Thread: { configurable: true, enumerable: true, writable: true, value: Thread },
        Instruction: { configurable: true, enumerable: true, writable: true, value: Instruction },
        ApiResolver: { configurable: true, enumerable: true, writable: true, value: ApiResolver }
    });
})();
