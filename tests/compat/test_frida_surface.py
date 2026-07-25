import json
import unittest
from pathlib import Path

import frida_surface


FRIDA_SOURCE = Path("/home/qiu/Android/frida")


class FridaSurfaceParserTests(unittest.TestCase):
    def test_extracts_c_function_lists_and_pointer_macros(self):
        source = r'''
static const JSCFunctionListEntry sample_entries[] =
{
  JS_CFUNC_DEF ("run", 0, run),
  JS_CGETSET_DEF ("value", get_value, set_value),
  GUMJS_EXPORT_NATIVE_POINTER_READ_WRITE ("U32", U32),
};
'''
        entries = frida_surface.extract_function_lists(source)["sample_entries"]
        self.assertEqual(
            entries,
            [
                {"name": "readU32", "kind": "function"},
                {"name": "run", "kind": "function"},
                {"name": "value", "kind": "property"},
                {"name": "writeU32", "kind": "function"},
            ],
        )

    def test_extracts_only_top_level_runtime_globals(self):
        source = r'''
Object.defineProperties(globalThis, {
  send: {
    value: function () {
      return { nested: true };
    }
  },
  rpc: {
    value: { exports: {} }
  }
});
'''
        self.assertEqual(frida_surface.extract_runtime_globals(source), ["send", "rpc"])

    def test_checked_in_spec_matches_readme(self):
        spec = frida_surface.load_json(frida_surface.SPEC_PATH)
        self.assertEqual(frida_surface.read_documented_globals(), spec["documentedGlobals"])

    def test_goal02_diagnostics_surface_is_pinned(self):
        spec = frida_surface.load_json(frida_surface.SPEC_PATH)
        globals_by_name = {entry["name"]: entry for entry in spec["globals"]}
        probes_by_path = {entry["path"]: entry for entry in spec["probes"]}

        for name, expected_type in {
            "Int64": "function",
            "UInt64": "function",
            "DebugSymbol": "function",
            "Thread": "object",
            "Backtracer": "object",
            "Instruction": "function",
            "ApiResolver": "function",
        }.items():
            self.assertEqual(globals_by_name[name]["type"], expected_type)

        for path, expected_type in {
            "Int64.prototype.add": "function",
            "UInt64.prototype.toJSON": "function",
            "DebugSymbol.fromAddress": "function",
            "DebugSymbol.findFunctionsMatching": "function",
            "Thread.backtrace": "function",
            "Backtracer.ACCURATE": "number",
            "Instruction.parse": "function",
            "ApiResolver.prototype.enumerateMatches": "function",
        }.items():
            self.assertEqual(probes_by_path[path]["type"], expected_type)

    def test_goal03_module_process_surface_is_pinned(self):
        spec = frida_surface.load_json(frida_surface.SPEC_PATH)
        globals_by_name = {entry["name"]: entry for entry in spec["globals"]}
        probes_by_path = {entry["path"]: entry for entry in spec["probes"]}
        areas_by_name = {entry["area"]: entry for entry in spec["compatibilityAreas"]}

        self.assertEqual(globals_by_name["Module"]["type"], "function")
        self.assertEqual(globals_by_name["Module"]["classification"], "compatible")
        for path in {
            "Process.getModuleByAddress",
            "Process.attachModuleObserver",
            "Process.attachThreadObserver",
            "Module.findGlobalExportByName",
            "Module.prototype.enumerateSections",
            "Module.prototype.enumerateDependencies",
            "Module.prototype.ensureInitialized",
            "Module.prototype.findSymbolByName",
            "ModuleMap",
            "ModuleMap.prototype.update",
        }:
            self.assertEqual(probes_by_path[path]["type"], "function")

        self.assertEqual(
            areas_by_name["Module and Process"]["missing"],
            ["runOnThread", "exception handler"],
        )

    def test_goal04_native_abi_surface_is_pinned(self):
        spec = frida_surface.load_json(frida_surface.SPEC_PATH)
        globals_by_name = {entry["name"]: entry for entry in spec["globals"]}
        probes_by_path = {entry["path"]: entry for entry in spec["probes"]}
        areas_by_name = {entry["area"]: entry for entry in spec["compatibilityAreas"]}

        for name in {"gc", "NativeFunction", "NativeCallback", "SystemFunction"}:
            self.assertEqual(globals_by_name[name]["type"], "function")
            self.assertEqual(globals_by_name[name]["classification"], "compatible")

        for path in {
            "gc",
            "NativeFunction.prototype.call",
            "NativeCallback.prototype.isNull",
            "SystemFunction.prototype.apply",
        }:
            self.assertEqual(probes_by_path[path]["type"], "function")

        self.assertEqual(areas_by_name["Native ABI"]["status"], "compatible")
        self.assertEqual(areas_by_name["Native ABI"]["missing"], [])

    @unittest.skipUnless(FRIDA_SOURCE.exists(), "local Frida source checkout is unavailable")
    def test_extracts_arm64_generated_writer_surface(self):
        baseline = frida_surface.build_baseline(FRIDA_SOURCE)
        sources = baseline["upstream"]["sources"]
        writer = sources["gumquickcodewriter.c"]
        relocator = sources["gumquickcoderelocator.c"]

        self.assertTrue(writer["generatedArm64Bindings"])
        self.assertTrue(relocator["generatedArm64Bindings"])
        self.assertIn("Arm64Writer", writer["classes"])
        self.assertIn("Arm64Relocator", relocator["classes"])

        writer_names = {entry["name"] for entry in writer["functionLists"]["gumjs_arm64_writer_entries"]}
        relocator_names = {
            entry["name"] for entry in relocator["functionLists"]["gumjs_arm64_relocator_entries"]
        }
        self.assertIn("putNop", writer_names)
        self.assertIn("putInstruction", writer_names)
        self.assertIn("readOne", relocator_names)
        self.assertIn("writeAll", relocator_names)

    def test_generated_json_is_valid_and_versioned(self):
        baseline = json.loads(frida_surface.JSON_OUTPUT.read_text(encoding="utf-8"))
        self.assertEqual(baseline["schemaVersion"], 1)
        self.assertEqual(baseline["fridaDevkitVersion"], "17.15.5")


if __name__ == "__main__":
    unittest.main()
