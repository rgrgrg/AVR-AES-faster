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
#============================================================================
#
# AES_ExpandLastKey128_T
#
# AES Key Expansion - 128 bits, S-box in FLASH (tiny keybuffer)
#
# Input   : STxx(key), XKEYPTR(&expanded_key[0][0])
# Output  : (memory)
# Modified: Z, RCON, STxx, KEYPTR(temp)
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
#define KEYPTR_L          r26
#define KEYPTR_H          r27
#define XKEYPTR_L         r28
#define XKEYPTR_H         r29
#define KEYPTR              X
#define XKEYPTR             Y

		.section .text.AES_ExpandLastKey128_T,"ax",@progbits

		.global AES_ExpandLastKey128_T
AES_ExpandLastKey128_T:
		push ST20
		push ST30
		push ST01
		push ST11
		push ST21
		push ST31
		push ST02
		push ST12
		push ST22
		push ST32
		push ST03
		push ST13
		push ST23
		push ST33
		push XKEYPTR_L
		push XKEYPTR_H
		movw KEYPTR_L,r24
		movw XKEYPTR_L,r22
#Load_State
		ld   ST00,KEYPTR+
		ld   ST01,KEYPTR+
		ld   ST02,KEYPTR+
		ld   ST03,KEYPTR+
		ld   ST10,KEYPTR+
		ld   ST11,KEYPTR+
		ld   ST12,KEYPTR+
		ld   ST13,KEYPTR+
		ld   ST20,KEYPTR+
		ld   ST21,KEYPTR+
		ld   ST22,KEYPTR+
		ld   ST23,KEYPTR+
		ld   ST30,KEYPTR+
		ld   ST31,KEYPTR+
		ld   ST32,KEYPTR+
		ld   ST33,KEYPTR+
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+2,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+3,r30
AES_ExpandLastKey128_T_start1:
		.global AES_ExpandLastKey128_T_start1
#endif
#------------- Real function starts here -------------
		ldi   zh,hi8(AES_SBox_F)
		ldi  RCON,1
100:
		mov   zl,ST30
		lpm  KEYPTR_L,Z
		mov   zl,ST31
		lpm  KEYPTR_H,Z
		eor  ST00,KEYPTR_H
		mov   zl,ST32
		lpm  KEYPTR_H,Z
		eor  ST01,KEYPTR_H
		mov   zl,ST33
		lpm  KEYPTR_H,Z
		eor  ST02,KEYPTR_H
		eor  ST03,KEYPTR_L
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
		cpi  RCON,0x6c
		brne 100b
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
#-------------- Real function ends here --------------
#ifdef AES_BENCHMARK
AES_ExpandLastKey128_T_end1:
		.global AES_ExpandLastKey128_T_end1
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+4,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+5,r30
#endif
		pop  XKEYPTR_H
		pop  XKEYPTR_L
		pop  ST33
		pop  ST23
		pop  ST13
		pop  ST03
		pop  ST32
		pop  ST22
		pop  ST12
		pop  ST02
		pop  ST31
		pop  ST21
		pop  ST11
		pop  ST01
		pop  ST30
		pop  ST20
		eor   r1, r1
		ret
#ifdef AES_BENCHMARK
AES_ExpandLastKey128_T_end:
		.global AES_ExpandLastKey128_T_end
#endif
		.size AES_ExpandLastKey128_T,.-AES_ExpandLastKey128_T

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
#undef KEYPTR_L
#undef KEYPTR_H
#undef XKEYPTR_L
#undef XKEYPTR_H
#undef KEYPTR
#undef XKEYPTR
