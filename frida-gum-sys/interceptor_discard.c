/* Compatibility bridge for release devkits predating Gum 8f514005. */
#include "frida-gum.h"

extern void _gum_interceptor_forget_all_hooks_in_range (
    const GumMemoryRange * range) __attribute__ ((weak));

void
gum_rs_interceptor_discard_hooks_in_range_c (const GumMemoryRange * range)
{
  if (_gum_interceptor_forget_all_hooks_in_range != NULL)
    _gum_interceptor_forget_all_hooks_in_range (range);
}
