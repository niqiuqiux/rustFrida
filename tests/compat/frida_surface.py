#!/usr/bin/env python3
"""Generate and verify the rustFrida/Frida API compatibility baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "tests/compat/rustfrida-surface.json"
JSON_OUTPUT = REPO_ROOT / "doc/frida-api-surface.json"
MARKDOWN_OUTPUT = REPO_ROOT / "doc/frida-api-surface.md"
DEVICE_OUTPUT = REPO_ROOT / "tests/device/rfhook_frida_surface.js"
WRITER_TABLE_PATH = REPO_ROOT / "quickjs-hook/src/jsapi/stalker_writer.rs"

# `dispose` stays in the JavaScript facade: the Stalker output writer is owned by
# Gum, so a script must not be able to tear it down mid-block.
FACADE_ONLY_WRITER_MEMBERS = {"dispose"}


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def find_matching_brace(source: str, opening: int) -> int:
    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "/" and next_char == "*":
                state = "block_comment"
                index += 1
            elif char == "/" and next_char == "/":
                state = "line_comment"
                index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state in {"string", "char"}:
            if char == "\\":
                index += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        elif state == "block_comment" and char == "*" and next_char == "/":
            state = "code"
            index += 1
        elif state == "line_comment" and char == "\n":
            state = "code"
        index += 1
    raise ValueError("unbalanced braces")


def extract_function_lists(source: str) -> dict[str, list[dict[str, str]]]:
    lists: dict[str, list[dict[str, str]]] = {}
    header = re.compile(r"static\s+const\s+JSCFunctionListEntry\s+(\w+)\[\]\s*=\s*\{")
    for match in header.finditer(source):
        opening = source.find("{", match.start())
        body = source[opening + 1 : find_matching_brace(source, opening)]
        entries: list[dict[str, str]] = []
        patterns = (
            ("function", r'JS_CFUNC_DEF\s*\(\s*"([^"]+)"'),
            ("property", r'JS_CGETSET_DEF\s*\(\s*"([^"]+)"'),
            ("property", r'JS_PROP_(?:STRING|INT32)_DEF\s*\(\s*"([^"]+)"'),
        )
        for kind, pattern in patterns:
            entries.extend({"name": name, "kind": kind} for name in re.findall(pattern, body))
        for mode, suffix in re.findall(
            r'GUMJS_EXPORT_NATIVE_POINTER_(READ_WRITE|READ|WRITE)\s*\(\s*"([^"]+)"', body
        ):
            if mode in {"READ_WRITE", "READ"}:
                entries.append({"name": f"read{suffix}", "kind": "function"})
            if mode in {"READ_WRITE", "WRITE"}:
                entries.append({"name": f"write{suffix}", "kind": "function"})
        lists[match.group(1)] = sorted(entries, key=lambda entry: (entry["name"], entry["kind"]))
    return lists


def extract_runtime_globals(source: str) -> list[str]:
    marker = "Object.defineProperties(globalThis, {"
    start = source.find(marker)
    if start == -1:
        raise ValueError("globalThis property block not found")
    opening = source.find("{", start)
    body = source[opening + 1 : find_matching_brace(source, opening)]
    names: list[str] = []
    depth = 0
    for line in body.splitlines():
        if depth == 0:
            match = re.match(r"\s{2}([A-Za-z_$][A-Za-z0-9_$]*):\s*\{", line)
            if match:
                names.append(match.group(1))
        depth += line.count("{") - line.count("}")
    return names


def generate_arm64_binding_sources(gum: Path, gumjs: Path) -> dict[str, str]:
    generator = gumjs / "generate-bindings.py"
    with tempfile.TemporaryDirectory(prefix="rustfrida-frida-bindings-") as temporary:
        output = Path(temporary)
        subprocess.run(
            [sys.executable, str(generator), str(output), str(gum / "gum")],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return {
            "code_writer": (output / "gumquickcodewriter-arm64.inc").read_text(encoding="utf-8"),
            "code_relocator": (output / "gumquickcoderelocator-arm64.inc").read_text(encoding="utf-8"),
        }


def extract_upstream(frida_source: Path) -> dict[str, Any]:
    gum = frida_source / "subprojects/frida-gum"
    gumjs = gum / "bindings/gumjs"
    script_source = (gumjs / "gumquickscript.c").read_text(encoding="utf-8")
    main_init = script_source[script_source.index("_gum_quick_core_init") : script_source.index("JS_FreeValue (ctx, global_obj)")]
    modules = []
    for name in re.findall(r"_gum_quick_([a-z0-9_]+)_init\s*\(", main_init):
        if name not in modules:
            modules.append(name)

    generated_arm64 = generate_arm64_binding_sources(gum, gumjs)
    files: dict[str, Any] = {}
    for module in modules:
        compact_name = module.replace("_", "")
        path = gumjs / f"gumquick{compact_name}.c"
        if not path.exists():
            raise FileNotFoundError(f"missing GumJS module source: {path}")
        source = path.read_text(encoding="utf-8")
        generated_source = generated_arm64.get(module)
        if generated_source is not None:
            source += "\n" + generated_source
        global_literals = sorted(
            set(
                re.findall(
                    r'JS_DefinePropertyValueStr\s*\(\s*ctx\s*,\s*ns\s*,\s*"([^"]+)"',
                    source,
                    flags=re.MULTILINE,
                )
            )
        )
        classes = sorted(set(re.findall(r'\.class_name\s*=\s*"([^"]+)"', source)))
        files[path.name] = {
            "module": module,
            "generatedArm64Bindings": generated_source is not None,
            "globalLiterals": global_literals,
            "classes": classes,
            "functionLists": extract_function_lists(source),
        }

    runtime_source = (gumjs / "runtime/core.js").read_text(encoding="utf-8")
    package_lock = load_json(frida_source / "subprojects/frida-core/src/barebone/package-lock.json")
    types_package = package_lock["packages"]["node_modules/@types/frida-gum"]
    return {
        "fridaRevision": run_git(frida_source, "rev-parse", "HEAD"),
        "fridaDescribe": run_git(frida_source, "describe", "--tags", "--always"),
        "fridaTagRevision": run_git(frida_source, "rev-list", "-n", "1", "17.15.5"),
        "gumRevision": run_git(gum, "rev-parse", "HEAD"),
        "gumDescribe": run_git(gum, "describe", "--tags", "--always"),
        "gumTagRevision": run_git(gum, "rev-list", "-n", "1", "17.15.5"),
        "typesVersion": types_package["version"],
        "modules": modules,
        "runtimeGlobals": extract_runtime_globals(runtime_source),
        "sources": files,
    }


def extract_writer_tables(source: str) -> dict[str, list[dict[str, str]]]:
    """Parse the ARM64 writer/relocator opcode tables out of the Rust facade.

    The Rust side is the single source of truth for opcode numbering, so the
    baseline reads it directly rather than keeping a second copy in sync.
    """
    # Keep the reported result names identical to `StalkerWriterResult::as_str`,
    # which is what the JavaScript facade receives.
    result_names = {"Void": "void", "Bool": "bool", "Unsigned": "uint", "Pointer": "pointer"}
    tables: dict[str, list[dict[str, str]]] = {}
    entry_pattern = re.compile(
        r"^\s*(?P<constant>[A-Z0-9_]+)\s*=>\s*\"(?P<name>[A-Za-z0-9]+)\","
        r"\s*\"(?P<spec>[a-zA-Z]*)\",\s*(?P<result>[A-Za-z]+),\s*(?P<kind>[A-Za-z]+);",
        re.MULTILINE,
    )
    for macro, table in (("stalker_writer_methods", "writer"), ("stalker_relocator_methods", "relocator")):
        invocation = f"{macro}! {{"
        start = source.index(invocation)
        end = find_matching_brace(source, start + len(invocation) - 1)
        entries = [
            {
                "name": match.group("name"),
                "constant": match.group("constant"),
                "argSpec": match.group("spec"),
                "result": result_names[match.group("result")],
                "kind": match.group("kind").lower(),
            }
            for match in entry_pattern.finditer(source[start:end])
        ]
        tables[table] = entries
    return tables


def read_writer_tables() -> dict[str, list[dict[str, str]]]:
    return extract_writer_tables(WRITER_TABLE_PATH.read_text(encoding="utf-8"))


def read_documented_globals() -> list[str]:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    heading = "### 全局对象一览"
    start = readme.index(heading)
    line = next(line for line in readme[start:].splitlines()[1:] if line.strip())
    return [token.removesuffix("()") for token in re.findall(r"`([^`]+)`", line)]


def build_baseline(frida_source: Path) -> dict[str, Any]:
    spec = load_json(SPEC_PATH)
    documented = read_documented_globals()
    if documented != spec["documentedGlobals"]:
        raise ValueError(
            "README global list differs from tests/compat/rustfrida-surface.json:\n"
            f"README: {documented}\n"
            f"spec:   {spec['documentedGlobals']}"
        )
    version = (REPO_ROOT / "frida-gum-sys/FRIDA_VERSION").read_text(encoding="utf-8").strip()
    return {
        "schemaVersion": 1,
        "fridaDevkitVersion": version,
        "upstream": extract_upstream(frida_source),
        "rustFrida": spec,
    }


def render_markdown(baseline: dict[str, Any]) -> str:
    upstream = baseline["upstream"]
    rustfrida = baseline["rustFrida"]
    lines = [
        "# Frida API Surface Baseline",
        "",
        "> Generated by `tests/compat/frida_surface.py`; do not edit manually.",
        "",
        "## Revisions",
        "",
        "| Component | Revision |",
        "| --- | --- |",
        f"| Gum devkit | `{baseline['fridaDevkitVersion']}` |",
        f"| Frida | `{upstream['fridaRevision']}` (`{upstream['fridaDescribe']}`) |",
        f"| frida-gum | `{upstream['gumRevision']}` (`{upstream['gumDescribe']}`) |",
        f"| @types/frida-gum | `{upstream['typesVersion']}` |",
        f"| rustFrida compatibility baseline | `{rustfrida['baselineRevision']}` |",
        "",
        "## Upstream Modules",
        "",
        ", ".join(f"`{name}`" for name in upstream["modules"]),
        "",
        "Runtime globals from upstream `runtime/core.js`: "
        + ", ".join(f"`{name}`" for name in upstream["runtimeGlobals"]),
        "",
        "## rustFrida Globals",
        "",
        "| Name | Expected type | Classification |",
        "| --- | --- | --- |",
    ]
    for entry in rustfrida["globals"]:
        lines.append(f"| `{entry['name']}` | `{entry['type']}` | {entry['classification']} |")
    for entry in rustfrida["optionalGlobals"]:
        lines.append(
            f"| `{entry['name']}` | `{entry['type']}` | {entry['classification']} (feature `{entry['feature']}`) |"
        )
    lines.extend(
        [
            "",
            "## Compatibility Areas",
            "",
            "| Area | Status | Roadmap goal | Missing upstream surface |",
            "| --- | --- | --- | --- |",
        ]
    )
    for area in rustfrida["compatibilityAreas"]:
        missing = ", ".join(f"`{name}`" for name in area["missing"])
        lines.append(f"| {area['area']} | {area['status']} | Goal {area['goal']} | {missing} |")
    lines.extend(
        [
            "",
            "## Verification",
            "",
            "```bash",
            "python3 tests/compat/frida_surface.py --check --frida-source /home/qiu/Android/frida",
            "```",
            "",
            "Device capability probe: `tests/device/rfhook_frida_surface.js`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_device_probe(spec: dict[str, Any]) -> str:
    globals_json = json.dumps(spec["globals"], ensure_ascii=False, separators=(",", ":"))
    optional_json = json.dumps(spec["optionalGlobals"], ensure_ascii=False, separators=(",", ":"))
    probes_json = json.dumps(spec["probes"], ensure_ascii=False, separators=(",", ":"))
    return f'''// Generated by tests/compat/frida_surface.py; do not edit manually.
(function () {{
    "use strict";

    var requiredGlobals = {globals_json};
    var optionalGlobals = {optional_json};
    var probes = {probes_json};

    function resolve(path) {{
        var value = globalThis;
        var parts = path.split(".");
        for (var index = 0; index !== parts.length; index++) {{
            if (value === null || value === undefined)
                return undefined;
            value = value[parts[index]];
        }}
        return value;
    }}

    function actualType(value) {{
        if (value === null)
            return "null";
        if (Array.isArray(value))
            return "array";
        return typeof value;
    }}

    var failures = [];
    var snapshot = {{ globals: {{}}, optionalGlobals: {{}}, probes: {{}} }};
    requiredGlobals.forEach(function (entry) {{
        var type = actualType(resolve(entry.name));
        snapshot.globals[entry.name] = type;
        if (type !== entry.type)
            failures.push(entry.name + ": expected " + entry.type + ", got " + type);
    }});
    optionalGlobals.forEach(function (entry) {{
        var type = actualType(resolve(entry.name));
        snapshot.optionalGlobals[entry.name] = type;
        if (type !== "undefined" && type !== entry.type)
            failures.push(entry.name + ": expected optional " + entry.type + ", got " + type);
    }});
    probes.forEach(function (entry) {{
        var type = actualType(resolve(entry.path));
        snapshot.probes[entry.path] = type;
        if (type !== entry.type)
            failures.push(entry.path + ": expected " + entry.type + ", got " + type);
    }});

    console.log("[frida-surface][JSON] " + JSON.stringify(snapshot));
    if (failures.length !== 0)
        throw new Error("Frida surface mismatch:\\n" + failures.join("\\n"));
    console.log("[frida-surface][READY] compatibility surface verified");
}})();
'''


def generated_outputs(frida_source: Path) -> dict[Path, str]:
    baseline = build_baseline(frida_source)
    spec = baseline["rustFrida"]
    return {
        JSON_OUTPUT: json.dumps(baseline, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        MARKDOWN_OUTPUT: render_markdown(baseline),
        DEVICE_OUTPUT: render_device_probe(spec),
    }


def check_outputs(outputs: dict[Path, str]) -> bool:
    clean = True
    for path, expected in outputs.items():
        actual = path.read_text(encoding="utf-8") if path.exists() else None
        if actual != expected:
            print(f"out of date: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            clean = False
    return clean


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--frida-source",
        type=Path,
        default=Path("/home/qiu/Android/frida"),
        help="Frida source checkout used as the upstream reference",
    )
    parser.add_argument("--check", action="store_true", help="verify generated files instead of updating them")
    args = parser.parse_args()

    outputs = generated_outputs(args.frida_source.resolve())
    if args.check:
        return 0 if check_outputs(outputs) else 1
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"updated {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
