import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
OAT_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "hook_engine_oat_patch.c"
SOURCE_INCLUDE = REPO_ROOT / "quickjs-hook" / "src"


class OatPatchPermissionTests(unittest.TestCase):
    def test_cross_page_write_rolls_back_and_retries_rx(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")

        source = textwrap.dedent(
            rf'''
            #include <stdarg.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <string.h>
            #include <sys/mman.h>

            static int oat_test_mprotect(void *addr, size_t len, int prot);
            #define mprotect oat_test_mprotect
            #include "{OAT_SOURCE}"
            #undef mprotect

            static int calls;
            static int fail_rx_once;
            static void *protected_addr[4];
            static size_t protected_len[4];
            static int protected_prot[4];

            void hook_log(const char *fmt, ...) {{
                (void) fmt;
            }}

            void hook_flush_cache(void *start, size_t size) {{
                (void) start;
                (void) size;
            }}

            static int oat_test_mprotect(void *addr, size_t len, int prot) {{
                protected_addr[calls] = addr;
                protected_len[calls] = len;
                protected_prot[calls] = prot;
                calls++;
                if (fail_rx_once && prot == (PROT_READ | PROT_EXEC)) {{
                    fail_rx_once = 0;
                    return -1;
                }}
                return 0;
            }}

            int main(void) {{
                enum {{ PAGE_SIZE = 4096, PATCH_SIZE = 16 }};
                static uint8_t code[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE)));
                uint8_t original[PATCH_SIZE];
                uint8_t replacement[PATCH_SIZE];
                uint8_t *patch = code + PAGE_SIZE - 8;

                for (size_t index = 0; index < PATCH_SIZE; index++) {{
                    original[index] = (uint8_t) index;
                    replacement[index] = (uint8_t) (0xa0 + index);
                }}
                memcpy(patch, original, PATCH_SIZE);
                fail_rx_once = 1;

                if (oat_write_patch_with_rollback(patch, replacement, original,
                                                  PATCH_SIZE, PAGE_SIZE, "test") == 0)
                    return 1;
                if (memcmp(patch, original, PATCH_SIZE) != 0)
                    return 2;
                if (calls != 3)
                    return 3;
                if (protected_addr[0] != code || protected_addr[1] != code ||
                    protected_addr[2] != code)
                    return 4;
                if (protected_len[0] != sizeof(code) || protected_len[1] != sizeof(code) ||
                    protected_len[2] != sizeof(code))
                    return 5;
                if (protected_prot[0] != (PROT_READ | PROT_WRITE | PROT_EXEC) ||
                    protected_prot[1] != (PROT_READ | PROT_EXEC) ||
                    protected_prot[2] != (PROT_READ | PROT_EXEC))
                    return 6;
                return 0;
            }}
            '''
        )

        with tempfile.TemporaryDirectory(prefix="rustfrida-oat-perm-") as temporary:
            temporary_path = Path(temporary)
            harness = temporary_path / "oat_permission_harness.c"
            executable = temporary_path / "oat_permission_harness"
            harness.write_text(source, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-unused-function",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-I",
                    str(SOURCE_INCLUDE),
                    str(harness),
                    "-Wl,--gc-sections",
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)
