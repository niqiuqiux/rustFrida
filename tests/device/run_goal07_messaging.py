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
SCRIPT = REPO_ROOT / "tests" / "device" / "rfhook_goal07_messaging.js"
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
            if "[JS error]" in line or "[goal07][FAIL]" in line:
                raise RuntimeError(line.strip())
            if "timer callbacks did not stop" in line:
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


def run_round(session):
    """Drive one full pass of the script, up to its READY marker."""
    session.wait_for(r"\[goal07\]\[ORDER-READY\] timers verified")
    session.wait_for(r"\[goal07\]\[RECV-WAITING\]")
    # Plain text is wrapped as {"type":"send","payload":...} by the host.
    session.send("post ping")
    session.wait_for(r"\[goal07\]\[RECV-ARMED\]")
    session.send('post {"type":"custom","payload":"pong"}')
    session.wait_for(r"\[goal07\]\[RECV-READY\] messaging verified")
    session.wait_for(r"\[goal07\]\[SCAN-READY\] Memory.scan promise verified")
    session.wait_for(r"\[goal07\]\[READY\] messaging and timers verified")


def main():
    parser = argparse.ArgumentParser(description="Run Goal 07 messaging and timer device regression")
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

    with tempfile.TemporaryDirectory(prefix="rf-goal07-") as temporary:
        temporary = Path(temporary)
        host = temporary / "rf_g07_host"
        # The script needs no native fixture, only a process to live in.
        run([
            str(clang), "-fPIE", "-pie", "-O2", "-g", "-Wl,--build-id=none",
            str(FIXTURES / "goal07_host.c"), "-o", str(host),
        ])

        device_rustfrida = f"{DEVICE_ROOT}/rustfrida-goal07"
        device_script = f"{DEVICE_ROOT}/{SCRIPT.name}"
        for local, remote in (
            (host, f"{DEVICE_ROOT}/{host.name}"),
            (SCRIPT, device_script),
            (args.rustfrida, device_rustfrida),
        ):
            adb_run("push", str(local), remote)
        root_shell(f"chmod 755 {device_rustfrida} {DEVICE_ROOT}/{host.name}; chmod 644 {device_script}")

    root_shell("kill $(pidof rf_g07_host) 2>/dev/null || true")
    tombstones_before = root_shell(
        "for f in /data/tombstones/*; do [ -f \"$f\" ] && stat -c '%n:%Y:%s' \"$f\"; done; true",
        capture=True,
    ).stdout.splitlines()
    start = root_shell(
        f"sh -c 'nohup {DEVICE_ROOT}/rf_g07_host >{DEVICE_ROOT}/rf_g07_host.log 2>&1 & echo $!'",
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

        run_round(session)
        # A repeating heartbeat is still armed here; %reload must retire it.
        session.send("%reload")
        run_round(session)

        # Heartbeats from the first runtime would show up as extra output after
        # the second round finished, so count them at the end.
        session.send("exit")
        if session.finish() != 0:
            raise RuntimeError("rustfrida exited with a non-zero status")

        output = "".join(session.output)
        if output.count("[goal07][READY]") != 2:
            raise RuntimeError("Goal 07 did not complete exactly once per runtime")
        if output.count("[goal07][ORDER-READY]") != 2:
            raise RuntimeError("the timer phase did not run once per runtime")
        if output.count("[goal07][RECV-READY]") != 2:
            raise RuntimeError("the messaging phase did not run once per runtime")
        # The host colourises the tag, so an ANSI reset sits between "[send]"
        # and the payload.
        if "[send]" not in output:
            raise RuntimeError("the host never received a send() message")
        if "(+4 bytes of data)" not in output:
            raise RuntimeError("the host never received the binary payload")
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
    print(f"[goal07-runner][PASS] target pid {host_pid} survived reload; timers and message handlers retired safely")


if __name__ == "__main__":
    main()
