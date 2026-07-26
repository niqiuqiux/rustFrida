#!/usr/bin/env python3

import argparse
import queue
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tests" / "device" / "rfhook_goal08_java.js"
DEVICE_ROOT = "/data/local/tmp"
PACKAGE = "com.example.rfhooktarget"


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

    def wait_for(self, pattern, timeout=90):
        matcher = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None and self.lines.empty():
                raise RuntimeError(f"rustfrida exited while waiting for {pattern}")
            try:
                line = self.lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if "[JS error]" in line or "[goal08][FAIL]" in line:
                raise RuntimeError(line.strip())
            match = matcher.search(line)
            if match is not None:
                return match
        raise TimeoutError(f"timed out waiting for {pattern}")

    def finish(self, timeout=60):
        return self.process.wait(timeout=timeout)

    def close(self):
        if self.process.poll() is None:
            try:
                self.send("exit")
                self.process.wait(timeout=15)
            except (BrokenPipeError, RuntimeError, subprocess.TimeoutExpired):
                self.process.kill()


def run(command, check=True, **kwargs):
    return subprocess.run(command, check=check, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description="Run Goal 08 Java facade device regression")
    parser.add_argument("--device", help="adb serial")
    parser.add_argument("--package", default=PACKAGE, help="target application package")
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

    if not args.rustfrida.is_file():
        raise RuntimeError(f"missing rustfrida binary: {args.rustfrida}")
    installed = root_shell(f"pm list packages {args.package}", capture=True).stdout
    if args.package not in installed:
        raise RuntimeError(f"{args.package} is not installed on the device")

    device_rustfrida = f"{DEVICE_ROOT}/rustfrida-goal08"
    device_script = f"{DEVICE_ROOT}/{SCRIPT.name}"
    for local, remote in ((SCRIPT, device_script), (args.rustfrida, device_rustfrida)):
        adb_run("push", str(local), remote)
    root_shell(f"chmod 755 {device_rustfrida}; chmod 644 {device_script}")

    root_shell(f"am force-stop {args.package}")
    tombstones_before = root_shell(
        "for f in /data/tombstones/*; do [ -f \"$f\" ] && stat -c '%n:%Y:%s' \"$f\"; done; true",
        capture=True,
    ).stdout.splitlines()

    session = None
    failure = None
    app_pid = None

    try:
        command = [
            *adb,
            "shell",
            "-tt",
            f"su -c {shlex.quote(f'{device_rustfrida} --spawn {args.package} -l {device_script}')}",
        ]
        session = Session(command)

        session.wait_for(r"\[goal08\]\[READY\] Java facade verified")
        # The compatibility layer is rebuilt with the runtime, so a reload has to
        # produce the same surface rather than a half-initialised Java object.
        session.send("%reload")
        session.wait_for(r"\[goal08\]\[READY\] Java facade verified")

        app_pid = root_shell(f"pidof {args.package}", capture=True, check=False).stdout.strip()
        session.send("exit")
        if session.finish() != 0:
            raise RuntimeError("rustfrida exited with a non-zero status")

        output = "".join(session.output)
        if output.count("[goal08][READY]") != 2:
            raise RuntimeError("Goal 08 did not complete exactly once per runtime")
        if "[goal08][FAIL]" in output:
            raise RuntimeError("a check reported a failure")
        for marker in ("Fatal signal", "SIGSEGV", "SIGABRT", "cleanup timeout", "drain timeout"):
            if marker in output:
                raise RuntimeError(f"fatal marker in output: {marker}")
    except BaseException as error:
        failure = error
    finally:
        if session is not None:
            session.close()
        survived = root_shell(f"pidof {args.package}", capture=True, check=False).stdout.strip()
        tombstones_after = root_shell(
            "for f in /data/tombstones/*; do [ -f \"$f\" ] && stat -c '%n:%Y:%s' \"$f\"; done; true",
            capture=True,
        ).stdout.splitlines()
        new_tombstones = sorted(set(tombstones_after) - set(tombstones_before))
        root_shell(f"am force-stop {args.package}", check=False)

    if new_tombstones:
        raise RuntimeError("new tombstone(s): " + ", ".join(new_tombstones)) from failure
    if not survived:
        raise RuntimeError(f"{args.package} did not survive the session") from failure
    if failure is not None:
        raise failure
    print(f"[goal08-runner][PASS] {args.package} (pid {app_pid or survived}) survived reload; Java facade verified")


if __name__ == "__main__":
    main()
