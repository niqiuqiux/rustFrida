import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WRITER_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "arm64_writer.c"
RELOCATOR_SOURCE = REPO_ROOT / "quickjs-hook" / "src" / "arm64_relocator.c"
WRITER_INCLUDE = WRITER_SOURCE.parent


class Arm64WriterTests(unittest.TestCase):
    def test_labels_and_encoding_failures_are_reported(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")

        source = textwrap.dedent(
            r'''
            #include <stdint.h>
            #include "arm64_writer.h"
            #include "arm64_relocator.h"

            static int check_labels_with_independent_pc(void) {
                uint8_t code[64] = { 0 };
                Arm64Writer writer;
                arm64_writer_init(&writer, code, 0x1000, sizeof(code));
                arm64_writer_put_b_label(&writer, 1);
                arm64_writer_put_nop(&writer);
                arm64_writer_put_label(&writer, 1);
                if (arm64_writer_flush(&writer) != 0)
                    return 1;
                if (*(uint32_t *) code != 0x14000002)
                    return 2;
                arm64_writer_clear(&writer);
                return 0;
            }

            static int check_failed_encodings(void) {
                uint8_t code[64] = { 0 };
                Arm64Writer writer;
                arm64_writer_init(&writer, code, 0x2000, sizeof(code));
                arm64_writer_put_fp_stp_offset(&writer, 0, 1, ARM64_REG_SP, 4);
                if (!writer.failed || arm64_writer_offset(&writer) != 0 ||
                    arm64_writer_flush(&writer) == 0)
                    return 1;
                arm64_writer_clear(&writer);

                arm64_writer_init(&writer, code, 0x2000, sizeof(code));
                arm64_writer_put_fp_ldp_post(&writer, 0, 1, ARM64_REG_SP, 512);
                if (!writer.failed || arm64_writer_offset(&writer) != 0 ||
                    arm64_writer_flush(&writer) == 0)
                    return 2;
                arm64_writer_clear(&writer);

                arm64_writer_init(&writer, code, 0x1000, sizeof(code));
                arm64_writer_put_adrp_reg_address(&writer, ARM64_REG_X0, 0x100001000ULL);
                if (!writer.failed || arm64_writer_offset(&writer) != 0 ||
                    arm64_writer_flush(&writer) == 0)
                    return 3;
                arm64_writer_clear(&writer);

                return 0;
            }

            static int check_capacity_and_ranges(void) {
                uint8_t code[4] = { 0 };
                Arm64Writer writer;
                arm64_writer_init(&writer, code, 0x3000, sizeof(code));
                arm64_writer_put_nop(&writer);
                arm64_writer_put_nop(&writer);
                if (!writer.failed || arm64_writer_offset(&writer) != sizeof(code) ||
                    arm64_writer_flush(&writer) == 0)
                    return 1;
                arm64_writer_clear(&writer);

                if (!arm64_writer_can_adrp_between(0x1000, 0x100000000ULL) ||
                    arm64_writer_can_adrp_between(0x1000, 0x100001000ULL))
                    return 2;
                return 0;
            }

            static int check_relocator_stops_at_unconditional_transfer(void) {
                uint32_t input[] = {
                    0x14000000, /* b . */
                    0xd503201f, /* must not be read by write_all() */
                };
                uint8_t code[64] = { 0 };
                Arm64Writer writer;
                Arm64Relocator relocator;
                arm64_writer_init(&writer, code, 0x2000, sizeof(code));
                arm64_relocator_init(&relocator, input, 0x1000, &writer);
                arm64_relocator_write_all(&relocator);
                if (!relocator.eob || !relocator.eoi ||
                    relocator.input_cur != (const uint8_t *) input + sizeof(uint32_t) ||
                    arm64_writer_offset(&writer) != sizeof(uint32_t) ||
                    arm64_writer_flush(&writer) != 0)
                    return 1;
                arm64_relocator_clear(&relocator);
                arm64_writer_clear(&writer);
                return 0;
            }

            int main(void) {
                int result = check_labels_with_independent_pc();
                if (result != 0)
                    return result;
                result = check_failed_encodings();
                if (result != 0)
                    return 10 + result;
                result = check_capacity_and_ranges();
                if (result != 0)
                    return 20 + result;
                result = check_relocator_stops_at_unconditional_transfer();
                if (result != 0)
                    return 30 + result;
                return 0;
            }
            '''
        )

        with tempfile.TemporaryDirectory(prefix="rustfrida-arm64-writer-") as temporary:
            temporary_path = Path(temporary)
            harness = temporary_path / "arm64_writer_harness.c"
            executable = temporary_path / "arm64_writer_harness"
            harness.write_text(source, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(WRITER_INCLUDE),
                    str(harness),
                    str(WRITER_SOURCE),
                    str(RELOCATOR_SOURCE),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)
