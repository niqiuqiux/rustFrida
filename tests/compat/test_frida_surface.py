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

    def test_goal05_stalker_writer_surface_is_pinned(self):
        spec = frida_surface.load_json(frida_surface.SPEC_PATH)
        probes_by_path = {entry["path"]: entry for entry in spec["probes"]}
        areas_by_name = {entry["area"]: entry for entry in spec["compatibilityAreas"]}
        globals_by_name = {entry["name"]: entry for entry in spec["globals"]}

        self.assertEqual(globals_by_name["Arm64Relocator"]["type"], "function")
        self.assertEqual(globals_by_name["Stalker"]["classification"], "compatible")
        self.assertEqual(probes_by_path["Stalker.statistics"]["type"], "function")

        self.assertEqual(areas_by_name["Stalker"]["status"], "compatible")
        self.assertEqual(areas_by_name["Stalker"]["missing"], [])

    def test_writer_opcode_table_is_well_formed(self):
        tables = frida_surface.read_writer_tables()

        for table in tables.values():
            names = [entry["name"] for entry in table]
            constants = [entry["constant"] for entry in table]
            self.assertEqual(len(names), len(set(names)), "duplicate method name")
            self.assertEqual(len(constants), len(set(constants)), "duplicate opcode constant")
            for entry in table:
                self.assertIn(entry["result"], {"void", "bool", "uint", "pointer"})
                self.assertIn(entry["kind"], {"function", "property"})
                if entry["kind"] == "property":
                    self.assertEqual(entry["argSpec"], "", f"{entry['name']} is a property but takes arguments")
                for character in entry["argSpec"]:
                    self.assertIn(character, "rcmusalbA", f"{entry['name']} uses an unknown spec character")

    def test_java_bridge_baseline_is_pinned(self):
        spec = frida_surface.read_java_bridge_spec()

        self.assertEqual(spec["package"], "frida-java-bridge")
        self.assertEqual(spec["version"], "7.0.12")
        self.assertTrue(spec["integrity"].startswith("sha512-"))
        self.assertEqual(len(spec["sha256"]), 64)

        # Every upstream member must be accounted for: implemented already, in
        # scope for Goal 08, or explicitly deferred. An unclassified member means
        # the pinned bridge moved and nobody looked.
        status = spec["rustFridaStatus"]
        categorised = set(status["implementedBeforeGoal08"]) | set(status["goal08"]) | set(status["deferred"])
        upstream = set(spec["upstreamMembers"])
        self.assertEqual(upstream - categorised, set(), "unclassified frida-java-bridge members")
        self.assertEqual(categorised - upstream, set(), "classified members the pinned bridge does not have")

    def test_java_bridge_version_matches_the_local_frida_checkout(self):
        lock_path = FRIDA_SOURCE / "subprojects/frida-tools/agents/tracer/package-lock.json"
        if not lock_path.exists():
            self.skipTest("local Frida source checkout is unavailable")

        spec = frida_surface.read_java_bridge_spec()
        lock = frida_surface.load_json(lock_path)
        entry = lock["packages"]["node_modules/frida-java-bridge"]
        self.assertEqual(entry["version"], spec["version"])
        self.assertEqual(entry["integrity"], spec["integrity"])

    def test_java_members_cover_the_goal08_scope(self):
        spec = frida_surface.read_java_bridge_spec()
        implemented = frida_surface.read_java_members()

        for name in spec["rustFridaStatus"]["implementedBeforeGoal08"]:
            self.assertIn(name, implemented, f"{name} was implemented before Goal 08 but is gone")
        for name in spec["rustFridaStatus"]["goal08"]:
            self.assertIn(name, implemented, f"{name} is in Goal 08 scope but is not defined")

    @unittest.skipUnless(FRIDA_SOURCE.exists(), "local Frida source checkout is unavailable")
    def test_writer_opcode_table_matches_upstream_arm64_surface(self):
        baseline = frida_surface.build_baseline(FRIDA_SOURCE)
        sources = baseline["upstream"]["sources"]
        tables = frida_surface.read_writer_tables()

        upstream_writer_entries = sources["gumquickcodewriter.c"]["functionLists"]["gumjs_arm64_writer_entries"]
        upstream_relocator_entries = sources["gumquickcoderelocator.c"]["functionLists"][
            "gumjs_arm64_relocator_entries"
        ]
        upstream_writer = {entry["name"] for entry in upstream_writer_entries}
        upstream_relocator = {entry["name"] for entry in upstream_relocator_entries}

        implemented_writer = {entry["name"] for entry in tables["writer"]}
        implemented_relocator = {entry["name"] for entry in tables["relocator"]}

        # A member modelled as a getter upstream must not become a callable here:
        # `relocator.eoi` and `writer.pc` are read, never invoked.
        upstream_kinds = {entry["name"]: entry["kind"] for entry in upstream_writer_entries}
        upstream_kinds.update({entry["name"]: entry["kind"] for entry in upstream_relocator_entries})
        for entry in tables["writer"] + tables["relocator"]:
            self.assertEqual(
                entry["kind"],
                upstream_kinds[entry["name"]],
                f"{entry['name']} is a {entry['kind']} here but a {upstream_kinds[entry['name']]} upstream",
            )

        self.assertEqual(
            upstream_writer - implemented_writer,
            frida_surface.FACADE_ONLY_WRITER_MEMBERS,
            "Arm64Writer members are missing from the rustFrida opcode table",
        )
        self.assertEqual(
            implemented_writer - upstream_writer,
            set(),
            "rustFrida exposes Arm64Writer members upstream does not have",
        )
        self.assertEqual(
            upstream_relocator - implemented_relocator,
            frida_surface.FACADE_ONLY_WRITER_MEMBERS,
            "Arm64Relocator members are missing from the rustFrida opcode table",
        )
        self.assertEqual(implemented_relocator - upstream_relocator, set())

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
