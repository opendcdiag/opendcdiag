# SPDX-License-Identifier: Apache-2.0

# This file forces the assembler not to emit aligned AVX instructions
# Regenerate with:
#  for i in vmovapd vmovaps vmovdqa vmovdqa32 vmovdqa64; do
#    printf '.macro %s args:vararg\n  %s \\args\n.endm\n' $i ${i/a/u}
#  done

.macro vmovapd args:vararg
  vmovupd \args
.endm
.macro vmovaps args:vararg
  vmovups \args
.endm
.macro vmovdqa args:vararg
  vmovdqu \args
.endm
.macro vmovdqa32 args:vararg
  vmovdqu32 \args
.endm
.macro vmovdqa64 args:vararg
  vmovdqu64 \args
.endm
