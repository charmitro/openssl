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
# - Vector ShangMi Suite: SM4 Block Cipher ('Zvksed')

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

####
# int rv64i_zvksed_sm4_set_encrypt_key(const unsigned char *userKey,
#                                      SM4_KEY *key);
#
{
my ($ukey,$keys,$fk)=("a0","a1","t0");
my ($vukey,$vfk,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_set_encrypt_key
.type rv64i_zvksed_sm4_set_encrypt_key,\@function
rv64i_zvksed_sm4_set_encrypt_key:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}

    # Load the user key
    @{[vle32_v $vukey, $ukey]}
    @{[vrev8_v $vukey, $vukey]}

    # Load the FK.
    la $fk, FK
    @{[vle32_v $vfk, $fk]}

    # Generate round keys.
    @{[vxor_vv $vukey, $vukey, $vfk]}
    @{[vsm4k_vi $vk0, $vukey, 0]} # rk[0:3]
    @{[vsm4k_vi $vk1, $vk0, 1]} # rk[4:7]
    @{[vsm4k_vi $vk2, $vk1, 2]} # rk[8:11]
    @{[vsm4k_vi $vk3, $vk2, 3]} # rk[12:15]
    @{[vsm4k_vi $vk4, $vk3, 4]} # rk[16:19]
    @{[vsm4k_vi $vk5, $vk4, 5]} # rk[20:23]
    @{[vsm4k_vi $vk6, $vk5, 6]} # rk[24:27]
    @{[vsm4k_vi $vk7, $vk6, 7]} # rk[28:31]

    # Store round keys
    @{[vse32_v $vk0, $keys]} # rk[0:3]
    addi $keys, $keys, 16
    @{[vse32_v $vk1, $keys]} # rk[4:7]
    addi $keys, $keys, 16
    @{[vse32_v $vk2, $keys]} # rk[8:11]
    addi $keys, $keys, 16
    @{[vse32_v $vk3, $keys]} # rk[12:15]
    addi $keys, $keys, 16
    @{[vse32_v $vk4, $keys]} # rk[16:19]
    addi $keys, $keys, 16
    @{[vse32_v $vk5, $keys]} # rk[20:23]
    addi $keys, $keys, 16
    @{[vse32_v $vk6, $keys]} # rk[24:27]
    addi $keys, $keys, 16
    @{[vse32_v $vk7, $keys]} # rk[28:31]

    li a0, 1
    ret
.size rv64i_zvksed_sm4_set_encrypt_key,.-rv64i_zvksed_sm4_set_encrypt_key
___
}

####
# int rv64i_zvksed_sm4_set_decrypt_key(const unsigned char *userKey,
#                                      SM4_KEY *key);
#
{
my ($ukey,$keys,$fk,$stride)=("a0","a1","t0","t1");
my ($vukey,$vfk,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_set_decrypt_key
.type rv64i_zvksed_sm4_set_decrypt_key,\@function
rv64i_zvksed_sm4_set_decrypt_key:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}

    # Load the user key
    @{[vle32_v $vukey, $ukey]}
    @{[vrev8_v $vukey, $vukey]}

    # Load the FK.
    la $fk, FK
    @{[vle32_v $vfk, $fk]}

    # Generate round keys.
    @{[vxor_vv $vukey, $vukey, $vfk]}
    @{[vsm4k_vi $vk0, $vukey, 0]} # rk[0:3]
    @{[vsm4k_vi $vk1, $vk0, 1]} # rk[4:7]
    @{[vsm4k_vi $vk2, $vk1, 2]} # rk[8:11]
    @{[vsm4k_vi $vk3, $vk2, 3]} # rk[12:15]
    @{[vsm4k_vi $vk4, $vk3, 4]} # rk[16:19]
    @{[vsm4k_vi $vk5, $vk4, 5]} # rk[20:23]
    @{[vsm4k_vi $vk6, $vk5, 6]} # rk[24:27]
    @{[vsm4k_vi $vk7, $vk6, 7]} # rk[28:31]

    # Store round keys in reverse order
    addi $keys, $keys, 12
    li $stride, -4
    @{[vsse32_v $vk7, $keys, $stride]} # rk[31:28]
    addi $keys, $keys, 16
    @{[vsse32_v $vk6, $keys, $stride]} # rk[27:24]
    addi $keys, $keys, 16
    @{[vsse32_v $vk5, $keys, $stride]} # rk[23:20]
    addi $keys, $keys, 16
    @{[vsse32_v $vk4, $keys, $stride]} # rk[19:16]
    addi $keys, $keys, 16
    @{[vsse32_v $vk3, $keys, $stride]} # rk[15:12]
    addi $keys, $keys, 16
    @{[vsse32_v $vk2, $keys, $stride]} # rk[11:8]
    addi $keys, $keys, 16
    @{[vsse32_v $vk1, $keys, $stride]} # rk[7:4]
    addi $keys, $keys, 16
    @{[vsse32_v $vk0, $keys, $stride]} # rk[3:0]

    li a0, 1
    ret
.size rv64i_zvksed_sm4_set_decrypt_key,.-rv64i_zvksed_sm4_set_decrypt_key
___
}

####
# void rv64i_zvksed_sm4_encrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_encrypt
.type rv64i_zvksed_sm4_encrypt,\@function
rv64i_zvksed_sm4_encrypt:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}

    # Order of elements was adjusted in set_encrypt_key()
    @{[vle32_v $vk0, $keys]} # rk[0:3]
    addi $keys, $keys, 16
    @{[vle32_v $vk1, $keys]} # rk[4:7]
    addi $keys, $keys, 16
    @{[vle32_v $vk2, $keys]} # rk[8:11]
    addi $keys, $keys, 16
    @{[vle32_v $vk3, $keys]} # rk[12:15]
    addi $keys, $keys, 16
    @{[vle32_v $vk4, $keys]} # rk[16:19]
    addi $keys, $keys, 16
    @{[vle32_v $vk5, $keys]} # rk[20:23]
    addi $keys, $keys, 16
    @{[vle32_v $vk6, $keys]} # rk[24:27]
    addi $keys, $keys, 16
    @{[vle32_v $vk7, $keys]} # rk[28:31]

    # Load input data
    @{[vle32_v $vdata, $in]}
    @{[vrev8_v $vdata, $vdata]}

    # Encrypt with all keys
    @{[vsm4r_vs $vdata, $vk0]}
    @{[vsm4r_vs $vdata, $vk1]}
    @{[vsm4r_vs $vdata, $vk2]}
    @{[vsm4r_vs $vdata, $vk3]}
    @{[vsm4r_vs $vdata, $vk4]}
    @{[vsm4r_vs $vdata, $vk5]}
    @{[vsm4r_vs $vdata, $vk6]}
    @{[vsm4r_vs $vdata, $vk7]}

    # Save the ciphertext (in reverse element order)
    @{[vrev8_v $vdata, $vdata]}
    li $stride, -4
    addi $out, $out, 12
    @{[vsse32_v $vdata, $out, $stride]}

    ret
.size rv64i_zvksed_sm4_encrypt,.-rv64i_zvksed_sm4_encrypt
___
}

####
# void rv64i_zvksed_sm4_decrypt(const unsigned char *in, unsigned char *out,
#                               const SM4_KEY *key);
#
{
my ($in,$out,$keys,$stride)=("a0","a1","a2","t0");
my ($vdata,$vk0,$vk1,$vk2,$vk3,$vk4,$vk5,$vk6,$vk7,$vgen)=("v1","v2","v3","v4","v5","v6","v7","v8","v9","v10");
$code .= <<___;
.p2align 3
.globl rv64i_zvksed_sm4_decrypt
.type rv64i_zvksed_sm4_decrypt,\@function
rv64i_zvksed_sm4_decrypt:
    @{[vsetivli__x0_4_e32_m1_ta_ma]}

    # Order of elements was adjusted in set_decrypt_key()
    @{[vle32_v $vk7, $keys]} # rk[31:28]
    addi $keys, $keys, 16
    @{[vle32_v $vk6, $keys]} # rk[27:24]
    addi $keys, $keys, 16
    @{[vle32_v $vk5, $keys]} # rk[23:20]
    addi $keys, $keys, 16
    @{[vle32_v $vk4, $keys]} # rk[19:16]
    addi $keys, $keys, 16
    @{[vle32_v $vk3, $keys]} # rk[15:11]
    addi $keys, $keys, 16
    @{[vle32_v $vk2, $keys]} # rk[11:8]
    addi $keys, $keys, 16
    @{[vle32_v $vk1, $keys]} # rk[7:4]
    addi $keys, $keys, 16
    @{[vle32_v $vk0, $keys]} # rk[3:0]

    # Load input data
    @{[vle32_v $vdata, $in]}
    @{[vrev8_v $vdata, $vdata]}

    # Encrypt with all keys
    @{[vsm4r_vs $vdata, $vk7]}
    @{[vsm4r_vs $vdata, $vk6]}
    @{[vsm4r_vs $vdata, $vk5]}
    @{[vsm4r_vs $vdata, $vk4]}
    @{[vsm4r_vs $vdata, $vk3]}
    @{[vsm4r_vs $vdata, $vk2]}
    @{[vsm4r_vs $vdata, $vk1]}
    @{[vsm4r_vs $vdata, $vk0]}

    # Save the ciphertext (in reverse element order)
    @{[vrev8_v $vdata, $vdata]}
    li $stride, -4
    addi $out, $out, 12
    @{[vsse32_v $vdata, $out, $stride]}

    ret
.size rv64i_zvksed_sm4_decrypt,.-rv64i_zvksed_sm4_decrypt
___
}

$code .= <<___;
# Family Key (little-endian 32-bit chunks)
.p2align 3
FK:
    .word 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
.size FK,.-FK
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
