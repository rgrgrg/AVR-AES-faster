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
# AES_Decrypt_R
#
# AES Decryption -  S-box in RAM
#
# Input   : STxx (ciphertext), ROUNDS, XKEYPTR(expanded_key+16*(nr+1))
# Output  : STxx (plaintext)
# Modified: Z, TMPx, ROUNDS, C_1B, XKEYPTR
#
# Data order: S00 S10 S20 S30 S01 S11 ... 
# Note: S00:S10,  S01:S11, S02:S12 S03:S13, TMP0:TMP1 must be pairs (movw) 
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
#define ROUNDS            r18
#define C_1B              r19
#define TMP0              r20
#define TMP1              r21
#define OUTADDR_L         r22
#define OUTADDR_H         r23
#define TMP2              r24
#define TMP3              r25
#define XKEYPTR_L         r26
#define XKEYPTR_H         r27
#define XKEYPTR             X

		.section .text.AES_Decrypt_R,"ax",@progbits

		.global AES_Decrypt_R
AES_Decrypt_R:
		ldi   zh,hi8(AES_InvSBox_R)
		ldi  C_1B,0x1b
#InvAddRoundKey
		ld   TMP0,-XKEYPTR
		eor  ST33,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST23,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST13,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST03,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST32,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST22,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST12,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST02,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST31,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST21,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST11,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST01,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST30,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST20,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST10,TMP0
		ld   TMP0,-XKEYPTR
		eor  ST00,TMP0
		dec  ROUNDS
100:
#InvSubBytesShiftRows
# row 0
		mov   zl,ST00
		ld   ST00,Z  
		mov   zl,ST01
		ld   ST01,Z  
		mov   zl,ST02
		ld   ST02,Z  
		mov   zl,ST03
		ld   ST03,Z  
# row 1
		mov   zl,ST13
		ld   TMP0,Z  
		mov   zl,ST12
		ld   ST13,Z  
		mov   zl,ST11
		ld   ST12,Z  
		mov   zl,ST10
		ld   ST11,Z  
# row 2
		mov   zl,ST20
		ld   TMP1,Z  
		mov   zl,ST21
		ld   TMP2,Z  
		mov   zl,ST22
		ld   ST20,Z  
		mov   zl,ST23
		ld   ST21,Z  
# row 3
		mov   zl,ST30
		ld   TMP3,Z  
		mov   zl,ST31
		ld   ST30,Z  
		mov   zl,ST32
		ld   ST31,Z  
		mov   zl,ST33
		ld   ST32,Z  
#InvAddRoundKey
		ld   ST33,-XKEYPTR
		eor  ST33,TMP3
		ld   ST23,-XKEYPTR
		eor  ST23,TMP2
		ld   TMP4,-XKEYPTR
		eor  ST13,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST03,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST32,TMP4
		ld   ST22,-XKEYPTR
		eor  ST22,TMP1
		ld   TMP4,-XKEYPTR
		eor  ST12,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST02,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST31,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST21,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST11,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST01,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST30,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST20,TMP4
		ld   ST10,-XKEYPTR
		eor  ST10,TMP0
		ld   TMP4,-XKEYPTR
		eor  ST00,TMP4
#InvMixColumns
# InvMixColumn(0)
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
		eor  ST00,TMP0
		eor  ST10,TMP1
		eor  ST20,TMP0
		eor  ST30,TMP1
		eor  ST20,TMP2
		eor  ST30,TMP2
		eor  TMP0,TMP1
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		mov  TMP1,TMP2
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
		eor  TMP1,TMP3
		eor  TMP0,TMP1
		eor  ST00,TMP0
		eor  ST20,TMP0
		eor  TMP0,TMP2
		eor  ST10,TMP0
		eor  ST30,TMP0
# InvMixColumn(1)
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
		eor  ST01,TMP0
		eor  ST11,TMP1
		eor  ST21,TMP0
		eor  ST31,TMP1
		eor  ST21,TMP2
		eor  ST31,TMP2
		eor  TMP0,TMP1
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		mov  TMP1,TMP2
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
		eor  TMP1,TMP3
		eor  TMP0,TMP1
		eor  ST01,TMP0
		eor  ST21,TMP0
		eor  TMP0,TMP2
		eor  ST11,TMP0
		eor  ST31,TMP0
# InvMixColumn(2)
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
		eor  ST02,TMP0
		eor  ST12,TMP1
		eor  ST22,TMP0
		eor  ST32,TMP1
		eor  ST22,TMP2
		eor  ST32,TMP2
		eor  TMP0,TMP1
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		mov  TMP1,TMP2
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
		eor  TMP1,TMP3
		eor  TMP0,TMP1
		eor  ST02,TMP0
		eor  ST22,TMP0
		eor  TMP0,TMP2
		eor  ST12,TMP0
		eor  ST32,TMP0
# InvMixColumn(3)
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
		eor  ST03,TMP0
		eor  ST13,TMP1
		eor  ST23,TMP0
		eor  ST33,TMP1
		eor  ST23,TMP2
		eor  ST33,TMP2
		eor  TMP0,TMP1
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
#   xtime2
		lsl  TMP2
		brcc 1f
		eor  TMP2,C_1B
1:
		mov  TMP1,TMP2
#   xtime2
		lsl  TMP1
		brcc 1f
		eor  TMP1,C_1B
1:
		eor  TMP1,TMP3
		eor  TMP0,TMP1
		eor  ST03,TMP0
		eor  ST23,TMP0
		eor  TMP0,TMP2
		eor  ST13,TMP0
		eor  ST33,TMP0
		dec  ROUNDS
		breq 1f ; exit
		rjmp 100b
1:
#InvSubBytesShiftRows
# row 0
		mov   zl,ST00
		ld   ST00,Z  
		mov   zl,ST01
		ld   ST01,Z  
		mov   zl,ST02
		ld   ST02,Z  
		mov   zl,ST03
		ld   ST03,Z  
# row 1
		mov   zl,ST13
		ld   TMP0,Z  
		mov   zl,ST12
		ld   ST13,Z  
		mov   zl,ST11
		ld   ST12,Z  
		mov   zl,ST10
		ld   ST11,Z  
# row 2
		mov   zl,ST20
		ld   TMP1,Z  
		mov   zl,ST21
		ld   TMP2,Z  
		mov   zl,ST22
		ld   ST20,Z  
		mov   zl,ST23
		ld   ST21,Z  
# row 3
		mov   zl,ST30
		ld   TMP3,Z  
		mov   zl,ST31
		ld   ST30,Z  
		mov   zl,ST32
		ld   ST31,Z  
		mov   zl,ST33
		ld   ST32,Z  
#InvAddRoundKey
		ld   ST33,-XKEYPTR
		eor  ST33,TMP3
		ld   ST23,-XKEYPTR
		eor  ST23,TMP2
		ld   TMP4,-XKEYPTR
		eor  ST13,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST03,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST32,TMP4
		ld   ST22,-XKEYPTR
		eor  ST22,TMP1
		ld   TMP4,-XKEYPTR
		eor  ST12,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST02,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST31,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST21,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST11,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST01,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST30,TMP4
		ld   TMP4,-XKEYPTR
		eor  ST20,TMP4
		ld   ST10,-XKEYPTR
		eor  ST10,TMP0
		ld   TMP4,-XKEYPTR
		eor  ST00,TMP4
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
#undef ROUNDS
#undef C_1B
#undef TMP0
#undef TMP1
#undef OUTADDR_L
#undef OUTADDR_H
#undef TMP2
#undef TMP3
#undef XKEYPTR_L
#undef XKEYPTR_H
#undef XKEYPTR
