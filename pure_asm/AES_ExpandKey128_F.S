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
# AES_ExpandKey128_F
#
# AES Key Expansion - 128 bits, S-box in FLASH
#
# Input   : STxx(key), XKEYPTR(&expanded_key[0][0])
# Output  : (memory)
# Modified: Z, RCON, STxx, TMPx
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
#define RCON              r25
#define TMP0              r26
#define TMP1              r27
#define XKEYPTR_L         r28
#define XKEYPTR_H         r29
#define XKEYPTR             Y

		.section .text.AES_ExpandKey128_F,"ax",@progbits

		.global AES_ExpandKey128_F
AES_ExpandKey128_F:
		ldi   zh,hi8(AES_SBox_F)
#nr=10 nk=4 4nr/nk=10 max_rcon=0x6c
		ldi  RCON,1
		rjmp 101f
100:
		mov   zl,ST30
		lpm  TMP0,Z
		mov   zl,ST31
		lpm  TMP1,Z
		eor  ST00,TMP1
		mov   zl,ST32
		lpm  TMP1,Z
		eor  ST01,TMP1
		mov   zl,ST33
		lpm  TMP1,Z
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
		cpi  RCON,0x6c
		brne 100b
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
#undef RCON
#undef TMP0
#undef TMP1
#undef XKEYPTR_L
#undef XKEYPTR_H
#undef XKEYPTR
