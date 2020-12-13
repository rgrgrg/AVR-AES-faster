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
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+0,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+1,r30
#endif
		push ST2X
		push ST3X
		push I
		push XKEYPTR_L
		push XKEYPTR_H
		movw KEYPTR_L,r24
		movw XKEYPTR_L,r22
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+2,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+3,r30
AES_ExpandKey_R_start1:
		.global AES_ExpandKey_R_start1
#endif
#------------- Real function starts here -------------
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
#-------------- Real function ends here --------------
#ifdef AES_BENCHMARK
AES_ExpandKey_R_end1:
		.global AES_ExpandKey_R_end1
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+4,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+5,r30
#endif
		pop  XKEYPTR_H
		pop  XKEYPTR_L
		pop  I
		pop  ST3X
		pop  ST2X
		eor   r1, r1
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+6,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+7,r30
#endif
		ret
#ifdef AES_BENCHMARK
AES_ExpandKey_R_end:
		.global AES_ExpandKey_R_end
#endif
		.size AES_ExpandKey_R,.-AES_ExpandKey_R

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
