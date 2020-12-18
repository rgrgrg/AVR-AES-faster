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


#============================================================================
#
# AES_InitInvBox_N
#
# AES GF(256) inverse multiplicative generator for Nano variant
#
# Input   : C_00(=0)
# Output  : None
# Modified: IBOXPTR, C_09, C_1B, INVVAL, TMP0, TMP1
#

#define C_00               r1
#define C_09              r18
#define C_1B              r19
#define INVVAL            r20
#define TMP0              r21
#define TMP1              r22
#define IBOXPTR_L         r26
#define IBOXPTR_H         r27
#define IBOXPTR             X

		.section .text.AES_InitInvBox_N,"ax",@progbits

		.global AES_InitInvBox_N
AES_InitInvBox_N:
#------------- Real function starts here -------------
		ldi  C_1B,0x1b
		ldi  C_09,0x09
		ldi  IBOXPTR_H,hi8(AES_InvBox_N)
		clr  IBOXPTR_L
		st   IBOXPTR,C_00
		ldi  IBOXPTR_L,1
		ldi  INVVAL,1
100:
		st   IBOXPTR,INVVAL
		mov  TMP0,IBOXPTR_L
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
		eor  IBOXPTR_L,TMP0
		mov  TMP0,INVVAL
		lsl  TMP0
		eor  INVVAL,TMP0
		mov  TMP0,INVVAL
		lsl  TMP0
		lsl  TMP0
		eor  INVVAL,TMP0
		mov  TMP0,INVVAL
		swap TMP0
		andi TMP0,0xf0
		eor  INVVAL,TMP0
		brpl 1f
		eor  INVVAL,C_09
1:
		cpi  IBOXPTR_L,1
		brne 100b
#-------------- Real function ends here --------------
		ret

		.size AES_InitInvBox_N,.-AES_InitInvBox_N

#undef C_00
#undef C_09
#undef C_1B
#undef INVVAL
#undef TMP0
#undef TMP1
#undef IBOXPTR_L
#undef IBOXPTR_H
#undef IBOXPTR
