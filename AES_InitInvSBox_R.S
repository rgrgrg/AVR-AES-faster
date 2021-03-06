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

#include "AVR-AES-Faster-devel.h"
#ifdef AES_BENCHMARK
#include <avr/io.h>
#endif

#============================================================================
#
# AES_InitInvSBox_R
#
# AES inverse S-Box generator for RAM variant
#
# Input   : C_00(=0)
# Output  : None
# Modified: ISBXPTR, C_09, C_1B, C_63, VAL, INVVAL, BOXVAL, TMP0, TMP1
#

#define C_00               r1
#define C_09              r18
#define C_1B              r19
#define C_63              r20
#define VAL               r21
#define INVVAL            r22
#define BOXVAL            r23
#define TMP0              r24
#define TMP1              r25
#define ISBXPTR_L         r26
#define ISBXPTR_H         r27
#define ISBXPTR             X

		.section .text.AES_InitInvSBox_R,"ax",@progbits

		.global AES_InitInvSBox_R
AES_InitInvSBox_R:
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+0,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+1,r30
#endif
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+2,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+3,r30
AES_InitInvSBox_R_start1:
		.global AES_InitInvSBox_R_start1
#endif
#------------- Real function starts here -------------
		ldi  C_63,0x63
		ldi  C_1B,0x1b
		ldi  C_09,0x09
		ldi  ISBXPTR_H,hi8(AES_InvSBox_R)
		mov  ISBXPTR_L,C_63
		st   ISBXPTR,C_00
		ldi  VAL,1
		ldi  INVVAL,1
100:
		mov  BOXVAL,INVVAL
		mov  TMP0,BOXVAL
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		eor  BOXVAL,C_63
		mov  ISBXPTR_L,BOXVAL
		st   ISBXPTR,VAL
		mov  BOXVAL,VAL
		mov  TMP0,BOXVAL
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		lsl  TMP0
		adc  TMP0,C_00
		eor  BOXVAL,TMP0
		eor  BOXVAL,C_63
		mov  ISBXPTR_L,BOXVAL
		st   ISBXPTR,INVVAL
		mov  TMP0,VAL
#   xtime2
		lsl  TMP0
		brcc 1f
		eor  TMP0,C_1B
1:
		eor  VAL,TMP0
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
		cpi  VAL,0xfb
		brne 100b
#-------------- Real function ends here --------------
#ifdef AES_BENCHMARK
AES_InitInvSBox_R_end1:
		.global AES_InitInvSBox_R_end1
		lds  r24,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+4,r24
		lds  r24,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+5,r24
#endif
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+6,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+7,r30
#endif
		ret
#ifdef AES_BENCHMARK
AES_InitInvSBox_R_end:
		.global AES_InitInvSBox_R_end
#endif

		.size AES_InitInvSBox_R,.-AES_InitInvSBox_R

#undef C_00
#undef C_09
#undef C_1B
#undef C_63
#undef VAL
#undef INVVAL
#undef BOXVAL
#undef TMP0
#undef TMP1
#undef ISBXPTR_L
#undef ISBXPTR_H
#undef ISBXPTR
