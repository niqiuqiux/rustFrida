function assertEqual(name, actual, expected) {
    if (String(actual) !== String(expected))
        throw new Error(name + ": expected " + expected + ", got " + actual);
    console.log("[cmodule-lifecycle][PASS] " + name + "=" + actual);
}

var module = new CModule(`
int rf_cmodule_add(int left, int right) {
    return left + right;
}
`);
var add = new NativeFunction(module.rf_cmodule_add, "int", ["int", "int"]);
assertEqual("native call", add(5, 7), 12);
assertEqual("builtins exposed", typeof CModule.builtins.headers["rfhook.h"], "string");
assertEqual("dispose prototype", typeof CModule.prototype.dispose, "function");
module.dropMetadata();
module.dispose();
module.dispose();
console.log("[cmodule-lifecycle][READY] CModule lifecycle verified");
