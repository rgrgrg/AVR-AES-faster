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
# AES_ExpandKey_R
#
# AES Key Expansion - universal (slow), S-box in RAM
#
# Input   : R_NK, R_NR, KEYPTR, XKEYPTR
# Output  : (memory)
# Modified: Z, STxx, I, I_MASK, I_NK, R_NR, KEYPTR, XKEYPTR, RCON,C_1B
#
# Note: TMP0:TMP1 must be pair (movw) 

#define ST0X               r0
#define ST1X               r1
#define ST2X               r2
#define ST3X               r3
#define I                  r4
#define R_NR              r18
#define I_MASK            r19
#define R_NK              r20
#define I_NK              r21
#define TMP0              r22
#define TMP1              r23
#define RCON              r25
#define KEYPTR_L          r26
#define KEYPTR_H          r27
#define XKEYPTR_L         r28
#define XKEYPTR_H         r29
#define KEYPTR              X
#define XKEYPTR             Y

		.section .text.AES_ExpandKey_R,"ax",@progbits

		.global AES_ExpandKey_R
AES_ExpandKey_R:
		ldi   zh,hi8(AES_SBox_R)
		movw TMP0,XKEYPTR_L
		mov  I,R_NK
1:
		ld   ST0X,KEYPTR+
		st   XKEYPTR+,ST0X
		ld   ST1X,KEYPTR+
		st   XKEYPTR+,ST1X
		ld   ST2X,KEYPTR+
		st   XKEYPTR+,ST2X
		ld   ST3X,KEYPTR+
		st   XKEYPTR+,ST3X
		dec  I
		brne 1b
		movw KEYPTR_L,TMP0
		ldi  RCON,1
		ldi  I_NK,1
		inc  R_NR
		lsl  R_NR
		lsl  R_NR
		eor  I_MASK,I_MASK
		cpi  R_NK,8
		brne 1f
		ldi  I_MASK,7
1:
		mov  I,R_NK
100:
		dec  I_NK
		brne 110f
		mov  I_NK,R_NK
# RotWord+SubWord
		mov  TMP0,ST0X
		mov   zl,ST1X
		ld   ST0X,Z  
		mov   zl,ST2X
		ld   ST1X,Z  
		mov   zl,ST3X
		ld   ST2X,Z  
		mov   zl,TMP0
		ld   ST3X,Z  
		eor  ST0X,RCON
#   xtime2_rcon
		lsl  RCON
		brcc 1f
		ldi  RCON,0x1b
1:
		rjmp 120f
110:
		mov  TMP0,I
		and  TMP0,I_MASK
		cpi  TMP0,4
		brne 120f
# SubWord
		mov   zl,ST0X
		ld   ST0X,Z  
		mov   zl,ST1X
		ld   ST1X,Z  
		mov   zl,ST2X
		ld   ST2X,Z  
		mov   zl,ST3X
		ld   ST3X,Z  
120:
		ld   TMP0,KEYPTR+
		eor  ST0X,TMP0
		st   XKEYPTR+,ST0X
		ld   TMP0,KEYPTR+
		eor  ST1X,TMP0
		st   XKEYPTR+,ST1X
		ld   TMP0,KEYPTR+
		eor  ST2X,TMP0
		st   XKEYPTR+,ST2X
		ld   TMP0,KEYPTR+
		eor  ST3X,TMP0
		st   XKEYPTR+,ST3X
		inc  I
		cp   I,R_NR
		brne 100b
		ret

#undef ST0X
#undef ST1X
#undef ST2X
#undef ST3X
#undef I
#undef R_NR
#undef I_MASK
#undef R_NK
#undef I_NK
#undef TMP0
#undef TMP1
#undef RCON
#undef KEYPTR_L
#undef KEYPTR_H
#undef XKEYPTR_L
#undef XKEYPTR_H
#undef KEYPTR
#undef XKEYPTR
