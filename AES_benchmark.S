#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#
#                                                                           #
#    AVR-AES-Faster Library                                                 #
#    (c) 2020 Rados³aw Gancarz <radgan99@gmail.com>                         #
#                                                                           #
#    This Source Code Form is subject to the terms of the Mozilla Public    #
#    License, v. 2.0. If a copy of the MPL was not distributed with this    #
#    file, You can obtain one at http://mozilla.org/MPL/2.0/.               #
#                                                                           #
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#

#include "AVR-AES-Faster-devel.h"
#ifdef AES_BENCHMARK
#include <avr/io.h>
#endif
#ifdef AES_BENCHMARK
		.section .text.benchmark_sizes,"ax",@progbits
		.balign 2
		.global benchmark_sizes
benchmark_sizes:
		.word AES_Encrypt_F_name, AES_Encrypt_F, AES_Encrypt_F_start1, AES_Encrypt_F_end1, AES_Encrypt_F_end
		.word AES_Encrypt_R_name, AES_Encrypt_R, AES_Encrypt_R_start1, AES_Encrypt_R_end1, AES_Encrypt_R_end
		.word AES_Decrypt_int_F_name, AES_Decrypt_int_F, AES_Decrypt_int_F_start1, AES_Decrypt_int_F_end1, AES_Decrypt_int_F_end
		.word AES_Decrypt_int_R_name, AES_Decrypt_int_R, AES_Decrypt_int_R_start1, AES_Decrypt_int_R_end1, AES_Decrypt_int_R_end
		.word AES_ExpandKey_F_name, AES_ExpandKey_F, AES_ExpandKey_F_start1, AES_ExpandKey_F_end1, AES_ExpandKey_F_end
		.word AES_ExpandKey_R_name, AES_ExpandKey_R, AES_ExpandKey_R_start1, AES_ExpandKey_R_end1, AES_ExpandKey_R_end
		.word AES_ExpandKey128_F_name, AES_ExpandKey128_F, AES_ExpandKey128_F_start1, AES_ExpandKey128_F_end1, AES_ExpandKey128_F_end
		.word AES_ExpandKey128_R_name, AES_ExpandKey128_R, AES_ExpandKey128_R_start1, AES_ExpandKey128_R_end1, AES_ExpandKey128_R_end
		.word AES_ExpandKey192_F_name, AES_ExpandKey192_F, AES_ExpandKey192_F_start1, AES_ExpandKey192_F_end1, AES_ExpandKey192_F_end
		.word AES_ExpandKey192_R_name, AES_ExpandKey192_R, AES_ExpandKey192_R_start1, AES_ExpandKey192_R_end1, AES_ExpandKey192_R_end
		.word AES_Encrypt128_T_name, AES_Encrypt128_T, AES_Encrypt128_T_start1, AES_Encrypt128_T_end1, AES_Encrypt128_T_end
		.word AES_Decrypt128_T_name, AES_Decrypt128_T, AES_Decrypt128_T_start1, AES_Decrypt128_T_end1, AES_Decrypt128_T_end
		.word AES_ExpandLastKey128_T_name, AES_ExpandLastKey128_T, AES_ExpandLastKey128_T_start1, AES_ExpandLastKey128_T_end1, AES_ExpandLastKey128_T_end
		.word AES_ExpandFirstKey128_T_name, AES_ExpandFirstKey128_T, AES_ExpandFirstKey128_T_start1, AES_ExpandFirstKey128_T_end1, AES_ExpandFirstKey128_T_end
		.word AES_InitInvBox_N_name, AES_InitInvBox_N, AES_InitInvBox_N_start1, AES_InitInvBox_N_end1, AES_InitInvBox_N_end
		.word AES_InitSBox_R_name, AES_InitSBox_R, AES_InitSBox_R_start1, AES_InitSBox_R_end1, AES_InitSBox_R_end
		.word AES_InitInvSBox_R_name, AES_InitInvSBox_R, AES_InitInvSBox_R_start1, AES_InitInvSBox_R_end1, AES_InitInvSBox_R_end
		.word AES_InitSBoxInvSBox_R_name, AES_InitSBoxInvSBox_R, AES_InitSBoxInvSBox_R_start1, AES_InitSBoxInvSBox_R_end1, AES_InitSBoxInvSBox_R_end
		.word 0
AES_Encrypt_F_name:
		.asciz "AES_Encrypt_F"
AES_Encrypt_R_name:
		.asciz "AES_Encrypt_R"
AES_Decrypt_int_F_name:
		.asciz "AES_Decrypt_int_F"
AES_Decrypt_int_R_name:
		.asciz "AES_Decrypt_int_R"
AES_ExpandKey_F_name:
		.asciz "AES_ExpandKey_F"
AES_ExpandKey_R_name:
		.asciz "AES_ExpandKey_R"
AES_ExpandKey128_F_name:
		.asciz "AES_ExpandKey128_F"
AES_ExpandKey128_R_name:
		.asciz "AES_ExpandKey128_R"
AES_ExpandKey192_F_name:
		.asciz "AES_ExpandKey192_F"
AES_ExpandKey192_R_name:
		.asciz "AES_ExpandKey192_R"
AES_Encrypt128_T_name:
		.asciz "AES_Encrypt128_T"
AES_Decrypt128_T_name:
		.asciz "AES_Decrypt128_T"
AES_ExpandLastKey128_T_name:
		.asciz "AES_ExpandLastKey128_T"
AES_ExpandFirstKey128_T_name:
		.asciz "AES_ExpandFirstKey128_T"
AES_InitInvBox_N_name:
		.asciz "AES_InitInvBox_N"
AES_InitSBox_R_name:
		.asciz "AES_InitSBox_R"
AES_InitInvSBox_R_name:
		.asciz "AES_InitInvSBox_R"
AES_InitSBoxInvSBox_R_name:
		.asciz "AES_InitSBoxInvSBox_R"
#endif