#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# The generated code of this file depends on the following RISC-V extensions:
# - RV64I
# - RISC-V vector ('V') with VLEN >= 128
# - Vector Bit-manipulation used in Cryptography ('Zvkb')
# - ShangMi Suite: SM3 Secure Hash ('Zvksh')

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin";
use lib "$Bin/../../perlasm";
use riscv;

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
my $output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
my $flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$output and open STDOUT,">$output";

my $code=<<___;
.text
___

################################################################################
# ossl_hwsm3_block_data_order_zvksh_lmul1(SM3_CTX *c, const void *p, size_t num);
{
$code .= <<___;
.text
.p2align 3
.globl ossl_hwsm3_block_data_order_zvksh_lmul1
.type ossl_hwsm3_block_data_order_zvksh_lmul1,\@function
ossl_hwsm3_block_data_order_zvksh_lmul1:
    @{[vsetivli__x0_8_e32_m1_ta_ma]}
___
$code .= zvksh_routine(1);
$code .= <<___;
    .size ossl_hwsm3_block_data_order_zvksh_lmul1,.-ossl_hwsm3_block_data_order_zvksh_lmul1

___
}

################################################################################
# ossl_hwsm3_block_data_order_zvksh_lmul2(SM3_CTX *c, const void *p, size_t num);
{
$code .= <<___;
.text
.p2align 3
.globl ossl_hwsm3_block_data_order_zvksh_lmul2
.type ossl_hwsm3_block_data_order_zvksh_lmul2,\@function
ossl_hwsm3_block_data_order_zvksh_lmul2:
    @{[vsetivli__x0_8_e32_m2_ta_ma]}
___
$code .= zvksh_routine(2);
$code .= <<___;
    .size ossl_hwsm3_block_data_order_zvksh_lmul2,.-ossl_hwsm3_block_data_order_zvksh_lmul2

___
}

sub zvksh_routine {
    my $lmul = shift;
    my ($CTX, $INPUT, $NUM) = ("a0", "a1", "a2");
    my ($V0, $V1, $V2, $V3, $V4) = ("v0", "v1", "v2", "v3", "v4");

    if ($lmul == 1) {
        ($V0, $V1, $V2, $V3, $V4) = ("v0", "v1", "v2", "v3", "v4");
    } elsif ($lmul == 2) {
        ($V0, $V1, $V2, $V3, $V4) = ("v0", "v2", "v4", "v6", "v8");
    }

my $ret=<<___;
    # Load initial state of hash context (c->A-H).
    @{[vle32_v $V0, $CTX]}
    @{[vrev8_v $V0, $V0]}

L_sm3_loop_lmul$lmul:
    # Copy the previous state to v1.
    # It will be XOR'ed with the current state at the end of the round.
    @{[vmv_v_v $V1, $V0]}

    # Load the 64B block in 2x32B chunks.
    @{[vle32_v $V3, $INPUT]} # v3 := {w0, ..., w7}
    add $INPUT, $INPUT, 32

    @{[vle32_v $V4, $INPUT]} # v4 := {w8, ..., w15}
    add $INPUT, $INPUT, 32

    add $NUM, $NUM, -1

    # As vsm3c consumes only w0, w1, w4, w5 we need to slide the input
    # 2 elements down so we process elements w2, w3, w6, w7
    # This will be repeated for each odd round.
    @{[vslidedown_vi $V2, $V3, 2]} # v2 := {w2, ..., w7, 0, 0}

    @{[vsm3c_vi $V0, $V3, 0]}
    @{[vsm3c_vi $V0, $V2, 1]}

    # Prepare a vector with {w4, ..., w11}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w4, ..., w7, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V4, 4]}   # v2 := {w4, w5, w6, w7, w8, w9, w10, w11}

    @{[vsm3c_vi $V0, $V2, 2]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w6, w7, w8, w9, w10, w11, 0, 0}
    @{[vsm3c_vi $V0, $V2, 3]}

    @{[vsm3c_vi $V0, $V4, 4]}
    @{[vslidedown_vi $V2, $V4, 2]} # v2 := {w10, w11, w12, w13, w14, w15, 0, 0}
    @{[vsm3c_vi $V0, $V2, 5]}

    @{[vsm3me_vv $V3, $V4, $V3]}  # v3 := {w16, w17, w18, w19, w20, w21, w22, w23}

    # Prepare a register with {w12, w13, w14, w15, w16, w17, w18, w19}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w12, w13, w14, w15, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V3, 4]}   # v2 := {w12, w13, w14, w15, w16, w17, w18, w19}

    @{[vsm3c_vi $V0, $V2, 6]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w14, w15, w16, w17, w18, w19, 0, 0}
    @{[vsm3c_vi $V0, $V2, 7]}

    @{[vsm3c_vi $V0, $V3, 8]}
    @{[vslidedown_vi $V2, $V3, 2]} # v2 := {w18, w19, w20, w21, w22, w23, 0, 0}
    @{[vsm3c_vi $V0, $V2, 9]}

    @{[vsm3me_vv $V4, $V3, $V4]} # v4 := {w24, w25, w26, w27, w28, w29, w30, w31}

    # Prepare a register with {w20, w21, w22, w23, w24, w25, w26, w27}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w20, w21, w22, w23, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V4, 4]}   # v2 := {w20, w21, w22, w23, w24, w25, w26, w27}

    @{[vsm3c_vi $V0, $V2, 10]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w22, w23, w24, w25, w26, w27, 0, 0}
    @{[vsm3c_vi $V0, $V2, 11]}

    @{[vsm3c_vi $V0, $V4, 12]}
    @{[vslidedown_vi $V2, $V4, 2]} # v2 := {w26, w27, w28, w29, w30, w31, 0, 0}
    @{[vsm3c_vi $V0, $V2, 13]}

    @{[vsm3me_vv $V3, $V4, $V3]} # v3 := {w32, w33, w34, w35, w36, w37, w38, w39}

    # Prepare a register with {w28, w29, w30, w31, w32, w33, w34, w35}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w28, w29, w30, w31, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V3, 4]}   # v2 := {w28, w29, w30, w31, w32, w33, w34, w35}

    @{[vsm3c_vi $V0, $V2, 14]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w30, w31, w32, w33, w34, w35, 0, 0}
    @{[vsm3c_vi $V0, $V2, 15]}

    @{[vsm3c_vi $V0, $V3, 16]}
    @{[vslidedown_vi $V2, $V3, 2]} # v2 := {w34, w35, w36, w37, w38, w39, 0, 0}
    @{[vsm3c_vi $V0, $V2, 17]}

    @{[vsm3me_vv $V4, $V3, $V4]}   # v4 := {w40, w41, w42, w43, w44, w45, w46, w47}

    # Prepare a register with {w36, w37, w38, w39, w40, w41, w42, w43}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w36, w37, w38, w39, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V4, 4]}   # v2 := {w36, w37, w38, w39, w40, w41, w42, w43}

    @{[vsm3c_vi $V0, $V2, 18]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w38, w39, w40, w41, w42, w43, 0, 0}
    @{[vsm3c_vi $V0, $V2, 19]}

    @{[vsm3c_vi $V0, $V4, 20]}
    @{[vslidedown_vi $V2, $V4, 2]} # v2 := {w42, w43, w44, w45, w46, w47, 0, 0}
    @{[vsm3c_vi $V0, $V2, 21]}

    @{[vsm3me_vv $V3, $V4, $V3]}   # v3 := {w48, w49, w50, w51, w52, w53, w54, w55}

    # Prepare a register with {w44, w45, w46, w47, w48, w49, w50, w51}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w44, w45, w46, w47, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V3, 4]}   # v2 := {w44, w45, w46, w47, w48, w49, w50, w51}

    @{[vsm3c_vi $V0, $V2, 22]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w46, w47, w48, w49, w50, w51, 0, 0}
    @{[vsm3c_vi $V0, $V2, 23]}

    @{[vsm3c_vi $V0, $V3, 24]}
    @{[vslidedown_vi $V2, $V3, 2]} # v2 := {w50, w51, w52, w53, w54, w55, 0, 0}
    @{[vsm3c_vi $V0, $V2, 25]}

    @{[vsm3me_vv $V4, $V3, $V4]}   # v4 := {w56, w57, w58, w59, w60, w61, w62, w63}

    # Prepare a register with {w52, w53, w54, w55, w56, w57, w58, w59}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w52, w53, w54, w55, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V4, 4]}   # v2 := {w52, w53, w54, w55, w56, w57, w58, w59}

    @{[vsm3c_vi $V0, $V2, 26]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w54, w55, w56, w57, w58, w59, 0, 0}
    @{[vsm3c_vi $V0, $V2, 27]}

    @{[vsm3c_vi $V0, $V4, 28]}
    @{[vslidedown_vi $V2, $V4, 2]} # v2 := {w58, w59, w60, w61, w62, w63, 0, 0}
    @{[vsm3c_vi $V0, $V2, 29]}

    @{[vsm3me_vv $V3, $V4, $V3]}   # v3 := {w64, w65, w66, w67, w68, w69, w70, w71}

    # Prepare a register with {w60, w61, w62, w63, w64, w65, w66, w67}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w60, w61, w62, w63, 0, 0, 0, 0}
    @{[vslideup_vi $V2, $V3, 4]}   # v2 := {w60, w61, w62, w63, w64, w65, w66, w67}

    @{[vsm3c_vi $V0, $V2, 30]}
    @{[vslidedown_vi $V2, $V2, 2]} # v2 := {w62, w63, w64, w65, w66, w67, 0, 0}
    @{[vsm3c_vi $V0, $V2, 31]}

    # XOR in the previous state.
    @{[vxor_vv $V0, $V0, $V1]}

    bnez $NUM, L_sm3_loop_lmul$lmul     # Check if there are any more block to process
L_sm3_end_lmul$lmul:
    @{[vrev8_v $V0, $V0]}
    @{[vse32_v $V0, $CTX]}
    ret
___
   return $ret;
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
