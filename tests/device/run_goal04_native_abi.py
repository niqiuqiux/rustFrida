#!/usr/bin/env python3

import argparse
import queue
import re
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "device" / "fixtures"
SCRIPT = REPO_ROOT / "tests" / "device" / "rfhook_goal04_native_abi.js"
DEVICE_ROOT = "/data/local/tmp"


class Session:
    def __init__(self, command):
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.lines = queue.Queue()
        self.output = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            print(line, end="")
            self.output.append(line)
            self.lines.put(line)

    def send(self, command):
        if self.process.poll() is not None:
            raise RuntimeError(f"rustfrida exited before command: {command}")
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def wait_for(self, pattern, timeout=60):
        matcher = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None and self.lines.empty():
                raise RuntimeError(f"rustfrida exited while waiting for {pattern}")
            try:
                line = self.lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if "[JS error]" in line or "[NativeCallback error]" in line or "[goal04][STALE-CALLBACK]" in line:
                raise RuntimeError(line.strip())
            match = matcher.search(line)
            if match is not None:
                return match
        raise TimeoutError(f"timed out waiting for {pattern}")

    def finish(self, timeout=45):
        return self.process.wait(timeout=timeout)

    def close(self):
        if self.process.poll() is None:
            try:
                self.send("exit")
                self.process.wait(timeout=10)
            except (BrokenPipeError, RuntimeError, subprocess.TimeoutExpired):
                self.process.kill()


def run(command, check=True, **kwargs):
    return subprocess.run(command, check=check, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description="Run Goal 04 Native ABI device regression")
    parser.add_argument("--device", help="adb serial")
    parser.add_argument(
        "--ndk",
        type=Path,
        default=Path("/home/qiu/Android/Sdk/ndk/29.0.14206865"),
    )
    parser.add_argument(
        "--rustfrida",
        type=Path,
        default=REPO_ROOT / "target" / "aarch64-linux-android" / "release" / "rustfrida",
    )
    args = parser.parse_args()

    adb = ["adb"] + (["-s", args.device] if args.device else [])

    def adb_run(*command, **kwargs):
        return run([*adb, *command], **kwargs)

    def root_shell(command, capture=False, check=True):
        return adb_run(
            "shell",
            f"su -c {shlex.quote(command)}",
            capture_output=capture,
            check=check,
        )

    toolchain = args.ndk / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin"
    clang = toolchain / "aarch64-linux-android21-clang"
    if not clang.is_file():
        raise RuntimeError(f"missing Android compiler: {clang}")
    if not args.rustfrida.is_file():
        raise RuntimeError(f"missing rustfrida binary: {args.rustfrida}")

    with tempfile.TemporaryDirectory(prefix="rf-goal04-") as temporary:
        temporary = Path(temporary)
        fixture = temporary / "librf_goal04_native_abi.so"
        host = temporary / "rf_g04_host"
        run([
            str(clang), "-shared", "-fPIC", "-O2", "-g", "-Wl,--build-id=none",
            "-Wl,-soname,librf_goal04_native_abi.so",
            str(FIXTURES / "goal04_native_abi.c"), "-pthread", "-o", str(fixture),
        ])
        run([
            str(clang), "-fPIE", "-pie", "-O2", "-g", "-Wl,--build-id=none",
            str(FIXTURES / "goal04_host.c"), "-ldl", "-o", str(host),
        ])

        device_rustfrida = f"{DEVICE_ROOT}/rustfrida-goal04"
        device_script = f"{DEVICE_ROOT}/{SCRIPT.name}"
        for local, remote in (
            (fixture, f"{DEVICE_ROOT}/{fixture.name}"),
            (host, f"{DEVICE_ROOT}/{host.name}"),
            (SCRIPT, device_script),
            (args.rustfrida, device_rustfrida),
        ):
            adb_run("push", str(local), remote)
        root_shell(
            f"chmod 755 {device_rustfrida} {DEVICE_ROOT}/{host.name}; "
            f"chmod 644 {DEVICE_ROOT}/{fixture.name} {device_script}"
        )

    root_shell("kill $(pidof rf_g04_host) 2>/dev/null || true")
    tombstones_before = root_shell(
        "for f in /data/tombstones/*; do [ -f \"$f\" ] && stat -c '%n:%Y:%s' \"$f\"; done; true",
        capture=True,
    ).stdout.splitlines()
    start = root_shell(
        f"sh -c 'nohup {DEVICE_ROOT}/rf_g04_host >{DEVICE_ROOT}/rf_g04_host.log 2>&1 & echo $!'",
        capture=True,
    )
    host_pid = int(start.stdout.strip().splitlines()[-1])
    session = None
    failure = None

    try:
        command = [
            *adb,
            "shell",
            "-tt",
            f"su -c {shlex.quote(f'{device_rustfrida} --pid {host_pid} -l {device_script}')}",
        ]
        session = Session(command)
        for round_number in (1, 2):
            session.wait_for(r"\[goal04\]\[READY\] native ABI verified")
            if round_number == 1:
                session.send("%reload")
        session.send("exit")
        if session.finish() != 0:
            raise RuntimeError("rustfrida exited with a non-zero status")

        output = "".join(session.output)
        if output.count("[goal04][READY]") != 2:
            raise RuntimeError("Goal 04 did not complete exactly once per runtime")
        if "[goal04][STALE-CALLBACK]" in output:
            raise RuntimeError("a NativeCallback from the previous runtime entered JavaScript")
        for marker in ("Fatal signal", "SIGSEGV", "SIGABRT", "cleanup timeout", "drain timeout"):
            if marker in output:
                raise RuntimeError(f"fatal marker in output: {marker}")
    except BaseException as error:
        failure = error
    finally:
        if session is not None:
            session.close()
        host_survived = root_shell(f"kill -0 {host_pid}", check=False).returncode == 0
        tombstones_after = root_shell(
            "for f in /data/tombstones/*; do [ -f \"$f\" ] && stat -c '%n:%Y:%s' \"$f\"; done; true",
            capture=True,
        ).stdout.splitlines()
        new_tombstones = sorted(set(tombstones_after) - set(tombstones_before))
        root_shell(f"kill {host_pid} 2>/dev/null || true")

    if new_tombstones:
        raise RuntimeError("new tombstone(s): " + ", ".join(new_tombstones)) from failure
    if not host_survived:
        raise RuntimeError(f"target pid {host_pid} did not survive") from failure
    if failure is not None:
        raise failure
    print(f"[goal04-runner][PASS] target pid {host_pid} survived reload; native callbacks retired safely")


if __name__ == "__main__":
    main()
