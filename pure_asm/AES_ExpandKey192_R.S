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
# AES_ExpandKey192_R
#
# AES Key Expansion - 192 bits, S-box in RAM
#
# Input   : STxx(key), XKEYPTR(&expanded_key[0][0])
# Output  : (memory)
# Modified: Z, RCON, STxx, TMPx
#

#define ST00               r0
#define ST10               r1
#define ST20               r2
#define ST30               r3
#define ST40               r4
#define ST50               r5
#define ST01               r6
#define ST11               r7
#define ST21               r8
#define ST31               r9
#define ST41              r10
#define ST51              r11
#define ST02              r12
#define ST12              r13
#define ST22              r14
#define ST32              r15
#define ST42              r16
#define ST52              r17
#define ST03              r18
#define ST13              r19
#define ST23              r20
#define ST33              r21
#define ST43              r22
#define ST53              r23
#define RCON              r25
#define TMP0              r26
#define TMP1              r27
#define XKEYPTR_L         r28
#define XKEYPTR_H         r29
#define XKEYPTR             Y

		.section .text.AES_ExpandKey192_R,"ax",@progbits

		.global AES_ExpandKey192_R
AES_ExpandKey192_R:
		ldi   zh,hi8(AES_SBox_R)
#nr=12 nk=6 4nr/nk=8 max_rcon=0x1b
		ldi  RCON,1
		rjmp 101f
100:
		mov   zl,ST50
		ld   TMP0,Z  
		mov   zl,ST51
		ld   TMP1,Z  
		eor  ST00,TMP1
		mov   zl,ST52
		ld   TMP1,Z  
		eor  ST01,TMP1
		mov   zl,ST53
		ld   TMP1,Z  
		eor  ST02,TMP1
		eor  ST03,TMP0
		eor  ST00,RCON
#   xtime2_rcon
		lsl  RCON
		brcc 1f
		ldi  RCON,0x1b
1:
		eor  ST10,ST00
		eor  ST11,ST01
		eor  ST12,ST02
		eor  ST13,ST03
		eor  ST20,ST10
		eor  ST21,ST11
		eor  ST22,ST12
		eor  ST23,ST13
		eor  ST30,ST20
		eor  ST31,ST21
		eor  ST32,ST22
		eor  ST33,ST23
		eor  ST40,ST30
		eor  ST41,ST31
		eor  ST42,ST32
		eor  ST43,ST33
		eor  ST50,ST40
		eor  ST51,ST41
		eor  ST52,ST42
		eor  ST53,ST43
101:
		st   XKEYPTR+,ST00
		st   XKEYPTR+,ST01
		st   XKEYPTR+,ST02
		st   XKEYPTR+,ST03
		st   XKEYPTR+,ST10
		st   XKEYPTR+,ST11
		st   XKEYPTR+,ST12
		st   XKEYPTR+,ST13
		st   XKEYPTR+,ST20
		st   XKEYPTR+,ST21
		st   XKEYPTR+,ST22
		st   XKEYPTR+,ST23
		st   XKEYPTR+,ST30
		st   XKEYPTR+,ST31
		st   XKEYPTR+,ST32
		st   XKEYPTR+,ST33
		cpi  RCON,0x1b
		breq 102f
		st   XKEYPTR+,ST40
		st   XKEYPTR+,ST41
		st   XKEYPTR+,ST42
		st   XKEYPTR+,ST43
		st   XKEYPTR+,ST50
		st   XKEYPTR+,ST51
		st   XKEYPTR+,ST52
		st   XKEYPTR+,ST53
		rjmp 100b
102:
		ret

#undef ST00
#undef ST10
#undef ST20
#undef ST30
#undef ST40
#undef ST50
#undef ST01
#undef ST11
#undef ST21
#undef ST31
#undef ST41
#undef ST51
#undef ST02
#undef ST12
#undef ST22
#undef ST32
#undef ST42
#undef ST52
#undef ST03
#undef ST13
#undef ST23
#undef ST33
#undef ST43
#undef ST53
#undef RCON
#undef TMP0
#undef TMP1
#undef XKEYPTR_L
#undef XKEYPTR_H
#undef XKEYPTR
