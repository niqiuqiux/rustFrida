#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "frida-gum-sys" / "FRIDA_GUM_DEVKIT.json"


def run(*args, cwd=None, env=None, capture=False):
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=capture,
    )


def git_output(repo, *args):
    return run("git", "-C", str(repo), *args, capture=True).stdout.strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_ndk_revision(ndk):
    properties = ndk / "source.properties"
    for line in properties.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "Pkg.Revision":
            return value.strip()
    raise RuntimeError(f"{properties} does not contain Pkg.Revision")


def require_clean_source(frida_source, gum_source, manifest):
    revisions = (
        (frida_source, manifest["fridaRevision"], "Frida"),
        (gum_source, manifest["gumRevision"], "frida-gum"),
    )
    for source, expected, label in revisions:
        actual = git_output(source, "rev-parse", "HEAD")
        if actual != expected:
            raise RuntimeError(f"{label} revision is {actual}, expected {expected}")
        dirty = git_output(source, "status", "--porcelain", "--untracked-files=no")
        if dirty:
            raise RuntimeError(f"{label} source has tracked changes:\n{dirty}")

    for commit in manifest["requiredFixes"]:
        result = subprocess.run(
            ["git", "-C", str(gum_source), "merge-base", "--is-ancestor", commit, "HEAD"]
        )
        if result.returncode != 0:
            raise RuntimeError(f"required Gum fix {commit} is not an ancestor of HEAD")


def verify_artifacts(devkit_dir, manifest):
    for label, artifact in manifest["artifacts"].items():
        path = devkit_dir / artifact["path"]
        if not path.is_file():
            raise RuntimeError(f"missing {label} artifact: {path}")
        actual_size = path.stat().st_size
        if actual_size != artifact["size"]:
            raise RuntimeError(
                f"{path} has size {actual_size}, expected {artifact['size']}"
            )
        actual_hash = sha256(path)
        if actual_hash != artifact["sha256"]:
            raise RuntimeError(
                f"{path} has SHA-256 {actual_hash}, expected {artifact['sha256']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Build and verify the pinned Android arm64 Frida Gum devkit"
    )
    parser.add_argument("--frida-source", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify an existing devkit without rebuilding it",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    gum_source = args.frida_source / "subprojects" / "frida-gum"
    devkit_dir = gum_source / "build" / "gum" / "devkit"

    require_clean_source(args.frida_source, gum_source, manifest)

    ndk_revision = read_ndk_revision(args.ndk)
    expected_ndk = manifest["toolchain"]["ndkRevision"]
    if ndk_revision != expected_ndk:
        raise RuntimeError(f"NDK revision is {ndk_revision}, expected {expected_ndk}")

    if not args.check:
        configure = [str(gum_source / "configure"), *manifest["configureArguments"]]
        environment = os.environ.copy()
        environment["ANDROID_NDK_ROOT"] = str(args.ndk.resolve())
        run(*configure, cwd=gum_source, env=environment)
        run("make", f"-j{args.jobs}", cwd=gum_source, env=environment)

    verify_artifacts(devkit_dir, manifest)
    print(f"verified Gum devkit: {devkit_dir}")
    print(f"export FRIDA_GUM_DEVKIT_DIR={devkit_dir}")


if __name__ == "__main__":
    main()
