#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#
#                                                                           #
#    AVR-AES-Faster Library                                                 #
#    (c) 2020 Rados�aw Gancarz <radgan99@gmail.com>                         #
#                                                                           #
#    This Source Code Form is subject to the terms of the Mozilla Public    #
#    License, v. 2.0. If a copy of the MPL was not distributed with this    #
#    file, You can obtain one at http://mozilla.org/MPL/2.0/.               #
#                                                                           #
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#


#============================================================================
#
# AES_Encrypt128_T
#
# AES Encryption -  S-box in FLASH (tiny keybuffer)
#
# Input   : STxx (plaintext), XKEYPTR(round_0_key) 
# Output  : STxx (ciphertext)
# Modified: Z, TMPx, R_CON, C_1B, XKEYPTR
#
# Data order: S00 S10 S20 S30 S01 S11 ... 
# Note: S00:S10,  S01:S11, S02:S12 S03:S13, TMP0:TMP1 must be pairs (movw) 
# Note: Key is modified (changed to round_11_key - need to replace 
# (or roll-back with ExpandFirstKey128)
#

#define ST00               r0
#define ST10               r1
#define ST20               r2
#define ST30               r3
#define ST01               r4
#define ST11               r5
#define ST21               r6
#define ST31               r7
#define ST02               r8
#define ST12               r9
#define ST22              r10
#define ST32              r11
#define ST03              r12
#define ST13              r13
#define ST23              r14
#define ST33              r15
#define TMP4              r16
#define R_CON             r18
#define C_1B              r19
#define TMP0              r20
#define TMP1              r21
#define OUTADDR_L         r22
#define OUTADDR_H         r23
#define TMP2              r24
#define TMP3              r25
#define KEYPTR_L          r26
#define KEYPTR_H          r27
#define KEYPTR              X

		.section .text.AES_Encrypt128_T,"ax",@progbits

		.global AES_Encrypt128_T
AES_Encrypt128_T:
		ldi   zh,hi8(AES_SBox_F)
		ldi  R_CON,1
		ldi  C_1B,0x1b
		rjmp 101f ; AddRoundKey
100:
#MixColumns
# MixColumn(0)
		movw TMP0,ST00
		mov  TMP2,ST20
		eor  TMP0,ST10
		eor  TMP1,ST20
		eor  TMP2,ST30
		mov  TMP3,TMP0
		eor  TMP3,TMP2
		mov  TMP2,TMP3
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		eor  TMP0,TMP3
		eor  TMP1,TMP3
		eor  ST00,TMP0
		eor  ST10,TMP1
		eor  ST20,TMP0
		eor  ST30,TMP1
		eor  ST20,TMP2
		eor  ST30,TMP2
# MixColumn(1)
		movw TMP0,ST01
		mov  TMP2,ST21
		eor  TMP0,ST11
		eor  TMP1,ST21
		eor  TMP2,ST31
		mov  TMP3,TMP0
		eor  TMP3,TMP2
		mov  TMP2,TMP3
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		eor  TMP0,TMP3
		eor  TMP1,TMP3
		eor  ST01,TMP0
		eor  ST11,TMP1
		eor  ST21,TMP0
		eor  ST31,TMP1
		eor  ST21,TMP2
		eor  ST31,TMP2
# MixColumn(2)
		movw TMP0,ST02
		mov  TMP2,ST22
		eor  TMP0,ST12
		eor  TMP1,ST22
		eor  TMP2,ST32
		mov  TMP3,TMP0
		eor  TMP3,TMP2
		mov  TMP2,TMP3
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		eor  TMP0,TMP3
		eor  TMP1,TMP3
		eor  ST02,TMP0
		eor  ST12,TMP1
		eor  ST22,TMP0
		eor  ST32,TMP1
		eor  ST22,TMP2
		eor  ST32,TMP2
# MixColumn(3)
		movw TMP0,ST03
		mov  TMP2,ST23
		eor  TMP0,ST13
		eor  TMP1,ST23
		eor  TMP2,ST33
		mov  TMP3,TMP0
		eor  TMP3,TMP2
		mov  TMP2,TMP3
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		eor  TMP0,TMP3
		eor  TMP1,TMP3
		eor  ST03,TMP0
		eor  ST13,TMP1
		eor  ST23,TMP0
		eor  ST33,TMP1
		eor  ST23,TMP2
		eor  ST33,TMP2
101:
#AddAndExpandKey
# RotWord+SubWord
		adiw KEYPTR,13
		ld    zl,KEYPTR+
		lpm  TMP0,Z
		ld    zl,KEYPTR+
		lpm  TMP1,Z
		ld    zl,KEYPTR+
		lpm  TMP2,Z
		sbiw KEYPTR,4
		ld    zl,KEYPTR
		lpm  TMP3,Z
		eor  TMP0,R_CON
		sbiw KEYPTR,12
# XOR, XOR, XOR...
		ld   TMP4,KEYPTR
		eor  ST00,TMP4
		eor  TMP0,TMP4
		st   KEYPTR+,TMP0
		ld   TMP4,KEYPTR
		eor  ST10,TMP4
		eor  TMP1,TMP4
		st   KEYPTR+,TMP1
		ld   TMP4,KEYPTR
		eor  ST20,TMP4
		eor  TMP2,TMP4
		st   KEYPTR+,TMP2
		ld   TMP4,KEYPTR
		eor  ST30,TMP4
		eor  TMP3,TMP4
		st   KEYPTR+,TMP3
		ld   TMP4,KEYPTR
		eor  ST01,TMP4
		eor  TMP0,TMP4
		st   KEYPTR+,TMP0
		ld   TMP4,KEYPTR
		eor  ST11,TMP4
		eor  TMP1,TMP4
		st   KEYPTR+,TMP1
		ld   TMP4,KEYPTR
		eor  ST21,TMP4
		eor  TMP2,TMP4
		st   KEYPTR+,TMP2
		ld   TMP4,KEYPTR
		eor  ST31,TMP4
		eor  TMP3,TMP4
		st   KEYPTR+,TMP3
		ld   TMP4,KEYPTR
		eor  ST02,TMP4
		eor  TMP0,TMP4
		st   KEYPTR+,TMP0
		ld   TMP4,KEYPTR
		eor  ST12,TMP4
		eor  TMP1,TMP4
		st   KEYPTR+,TMP1
		ld   TMP4,KEYPTR
		eor  ST22,TMP4
		eor  TMP2,TMP4
		st   KEYPTR+,TMP2
		ld   TMP4,KEYPTR
		eor  ST32,TMP4
		eor  TMP3,TMP4
		st   KEYPTR+,TMP3
		ld   TMP4,KEYPTR
		eor  ST03,TMP4
		eor  TMP0,TMP4
		st   KEYPTR+,TMP0
		ld   TMP4,KEYPTR
		eor  ST13,TMP4
		eor  TMP1,TMP4
		st   KEYPTR+,TMP1
		ld   TMP4,KEYPTR
		eor  ST23,TMP4
		eor  TMP2,TMP4
		st   KEYPTR+,TMP2
		ld   TMP4,KEYPTR
		eor  ST33,TMP4
		eor  TMP3,TMP4
		st   KEYPTR+,TMP3
		sbiw KEYPTR,16
#SubBytesShiftRows
# row 0
		mov   zl,ST00
		lpm  ST00,Z
		mov   zl,ST01
		lpm  ST01,Z
		mov   zl,ST02
		lpm  ST02,Z
		mov   zl,ST03
		lpm  ST03,Z
# row 1
		mov  TMP0,ST10
		mov   zl,ST11
		lpm  ST10,Z
		mov   zl,ST12
		lpm  ST11,Z
		mov   zl,ST13
		lpm  ST12,Z
		mov   zl,TMP0
		lpm  ST13,Z
# row 2
		mov  TMP0,ST20
		mov  TMP1,ST21
		mov   zl,ST22
		lpm  ST20,Z
		mov   zl,ST23
		lpm  ST21,Z
		mov   zl,TMP0
		lpm  ST22,Z
		mov   zl,TMP1
		lpm  ST23,Z
# row 3
		mov  TMP0,ST33
		mov   zl,ST32
		lpm  ST33,Z
		mov   zl,ST31
		lpm  ST32,Z
		mov   zl,ST30
		lpm  ST31,Z
		mov   zl,TMP0
		lpm  ST30,Z
		cpi  R_CON,0x36
		breq 102f ; exit
#   xtime2_rcon
		lsl  R_CON
		brcc 1f
		ldi  R_CON,0x1b
1:
		rjmp 100b ; loop
102:
#AddAndExpandKey
# Last Round
		ld   TMP4,KEYPTR+
		eor  ST00,TMP4
		ld   TMP4,KEYPTR+
		eor  ST10,TMP4
		ld   TMP4,KEYPTR+
		eor  ST20,TMP4
		ld   TMP4,KEYPTR+
		eor  ST30,TMP4
		ld   TMP4,KEYPTR+
		eor  ST01,TMP4
		ld   TMP4,KEYPTR+
		eor  ST11,TMP4
		ld   TMP4,KEYPTR+
		eor  ST21,TMP4
		ld   TMP4,KEYPTR+
		eor  ST31,TMP4
		ld   TMP4,KEYPTR+
		eor  ST02,TMP4
		ld   TMP4,KEYPTR+
		eor  ST12,TMP4
		ld   TMP4,KEYPTR+
		eor  ST22,TMP4
		ld   TMP4,KEYPTR+
		eor  ST32,TMP4
		ld   TMP4,KEYPTR+
		eor  ST03,TMP4
		ld   TMP4,KEYPTR+
		eor  ST13,TMP4
		ld   TMP4,KEYPTR+
		eor  ST23,TMP4
		ld   TMP4,KEYPTR+
		eor  ST33,TMP4
		ret

#undef ST00
#undef ST10
#undef ST20
#undef ST30
#undef ST01
#undef ST11
#undef ST21
#undef ST31
#undef ST02
#undef ST12
#undef ST22
#undef ST32
#undef ST03
#undef ST13
#undef ST23
#undef ST33
#undef TMP4
#undef R_CON
#undef C_1B
#undef TMP0
#undef TMP1
#undef OUTADDR_L
#undef OUTADDR_H
#undef TMP2
#undef TMP3
#undef KEYPTR_L
#undef KEYPTR_H
#undef KEYPTR
