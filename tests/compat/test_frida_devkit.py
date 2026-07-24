import hashlib
import json
import os
import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "frida-gum-sys" / "FRIDA_GUM_DEVKIT.json"
FRIDA_SOURCE = Path("/home/qiu/Android/frida")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FridaDevkitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_records_reproducible_source_and_toolchain(self):
        manifest = self.manifest
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["kind"], "gum")
        self.assertRegex(manifest["fridaRevision"], r"^[0-9a-f]{40}$")
        self.assertRegex(manifest["gumRevision"], r"^[0-9a-f]{40}$")
        self.assertIn(
            "8f51400554b0d16a4a383a901b01040687fd7f80",
            manifest["requiredFixes"],
        )
        self.assertEqual(manifest["target"]["os"], "android")
        self.assertEqual(manifest["target"]["arch"], "aarch64")
        self.assertEqual(manifest["toolchain"]["ndkRevision"], "29.0.14206865")
        self.assertEqual(
            manifest["configureArguments"][0], "--host=android-arm64"
        )

        for artifact in manifest["artifacts"].values():
            self.assertGreater(artifact["size"], 0)
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]))

    def test_build_script_and_cargo_use_the_same_manifest(self):
        build_script = (REPO_ROOT / "frida-gum-sys" / "build.rs").read_text(
            encoding="utf-8"
        )
        devkit_script = (REPO_ROOT / "scripts" / "build-frida-gum-devkit.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('include_str!("FRIDA_GUM_DEVKIT.json")', build_script)
        self.assertIn("FRIDA_GUM_DEVKIT_DIR", build_script)
        self.assertIn('"FRIDA_GUM_DEVKIT.json"', devkit_script)

    def test_selected_devkits_use_the_modern_interceptor_abi(self):
        build_script = (REPO_ROOT / "frida-gum-sys" / "build.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'if include_dir.is_some() {\n        println!("cargo:rustc-cfg=frida_gum_modern_interceptor")',
            build_script,
        )

    @unittest.skipUnless(FRIDA_SOURCE.exists(), "local Frida source checkout is unavailable")
    def test_local_source_matches_manifest_and_contains_required_fix(self):
        gum_source = FRIDA_SOURCE / "subprojects" / "frida-gum"

        def revision(source):
            return subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
            ).strip()

        self.assertEqual(revision(FRIDA_SOURCE), self.manifest["fridaRevision"])
        self.assertEqual(revision(gum_source), self.manifest["gumRevision"])
        for commit in self.manifest["requiredFixes"]:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(gum_source),
                    "merge-base",
                    "--is-ancestor",
                    commit,
                    "HEAD",
                ],
                check=True,
            )

    @unittest.skipUnless(
        os.environ.get("FRIDA_GUM_DEVKIT_DIR"),
        "FRIDA_GUM_DEVKIT_DIR is not set",
    )
    def test_selected_local_devkit_matches_manifest(self):
        devkit_dir = Path(os.environ["FRIDA_GUM_DEVKIT_DIR"])
        for artifact in self.manifest["artifacts"].values():
            path = devkit_dir / artifact["path"]
            self.assertEqual(path.stat().st_size, artifact["size"])
            self.assertEqual(sha256(path), artifact["sha256"])


if __name__ == "__main__":
    unittest.main()
