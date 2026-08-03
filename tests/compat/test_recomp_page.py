import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RECOMP_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "recomp" / "recomp_page.c"
WRITER_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "arm64_writer.c"
RELOCATOR_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "arm64_relocator.c"
SOURCE_INCLUDE = REPO_ROOT / "quickjs-hook" / "src"


class RecompPageTests(unittest.TestCase):
    def test_recompile_uses_runtime_16k_page_size(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")

        source = textwrap.dedent(
            r'''
            #include <stdarg.h>
            #include <stdint.h>
            #include <string.h>
            #include "recomp/recomp_page.h"

            void hook_log(const char *fmt, ...) {
                (void) fmt;
            }

            static int check_runtime_16k_page(void) {
                enum { PAGE_SIZE = 16 * 1024, INSN_COUNT = PAGE_SIZE / 4 };
                uint32_t original[INSN_COUNT];
                uint32_t recompiled[INSN_COUNT];
                uint8_t trampoline[PAGE_SIZE];
                RecompileStats stats;
                size_t trampoline_used = 0;

                for (size_t index = 0; index < INSN_COUNT; index++)
                    original[index] = 0xd503201f;
                memset(recompiled, 0, sizeof(recompiled));
                memset(trampoline, 0, sizeof(trampoline));

                if (recompile_page(original, 0x10000, recompiled, 0x20000,
                                   PAGE_SIZE, trampoline, 0x30000,
                                   sizeof(trampoline), &trampoline_used, 0,
                                   NULL, NULL, &stats) != 0)
                    return 1;
                if (recompiled[0] != original[0] ||
                    recompiled[INSN_COUNT - 2] != original[INSN_COUNT - 2])
                    return 2;
                if ((recompiled[INSN_COUNT - 1] & 0xfc000000u) != 0x14000000u)
                    return 3;
                if (stats.num_copied != INSN_COUNT - 1 ||
                    stats.num_trampolines != 1 || trampoline_used == 0)
                    return 4;
                return 0;
            }

            static int check_invalid_page_size(void) {
                uint32_t original[4] = { 0 };
                uint32_t recompiled[4] = { 0 };
                uint8_t trampoline[64] = { 0 };
                RecompileStats stats;

                if (recompile_page(original, 0x10000, recompiled, 0x20000,
                                   4098, trampoline, 0x30000,
                                   sizeof(trampoline), NULL, 0,
                                   NULL, NULL, &stats) == 0)
                    return 1;
                return stats.error == 0;
            }

            int main(void) {
                int result = check_runtime_16k_page();
                if (result != 0)
                    return result;
                return check_invalid_page_size() == 0 ? 0 : 10;
            }
            '''
        )

        with tempfile.TemporaryDirectory(prefix="rustfrida-recomp-page-") as temporary:
            temporary_path = Path(temporary)
            harness = temporary_path / "recomp_page_harness.c"
            executable = temporary_path / "recomp_page_harness"
            harness.write_text(source, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-unused-function",
                    "-I",
                    str(SOURCE_INCLUDE),
                    str(harness),
                    str(RECOMP_SOURCE),
                    str(WRITER_SOURCE),
                    str(RELOCATOR_SOURCE),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)
