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
# AES_Encrypt_R
#
# AES Encryption -  S-box in RAM
#
# Input   : STxx (plaintext), ROUNDS, XKEYPTR(expanded_key) 
# Output  : STxx (ciphertext)
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

		.section .text.AES_Encrypt_R,"ax",@progbits

		.global AES_Encrypt_R
AES_Encrypt_R:
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
		push TMP4
		movw XKEYPTR_L,r24
##Load16_Data
		ld   ST00,XKEYPTR+
		ld   ST10,XKEYPTR+
		ld   ST20,XKEYPTR+
		ld   ST30,XKEYPTR+
		ld   ST01,XKEYPTR+
		ld   ST11,XKEYPTR+
		ld   ST21,XKEYPTR+
		ld   ST31,XKEYPTR+
		ld   ST02,XKEYPTR+
		ld   ST12,XKEYPTR+
		ld   ST22,XKEYPTR+
		ld   ST32,XKEYPTR+
		ld   ST03,XKEYPTR+
		ld   ST13,XKEYPTR+
		ld   ST23,XKEYPTR+
		ld   ST33,XKEYPTR+
		movw XKEYPTR_L,r20
#ifdef AES_BENCHMARK
		lds  r30,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+2,r30
		lds  r30,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+3,r30
AES_Encrypt_R_start1:
		.global AES_Encrypt_R_start1
#endif
#------------- Real function starts here -------------
		ldi   zh,hi8(AES_SBox_R)
		ldi  C_1B,0x1b
		rjmp 100f
101:
#SubBytesShiftRows
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
		mov   zl,ST11
		ld   ST10,Z  
		mov   zl,ST12
		ld   ST11,Z  
		mov   zl,ST13
		ld   ST12,Z  
		mov   zl,TMP0
		ld   ST13,Z  
# row 2
		mov   zl,ST22
		ld   ST20,Z  
		mov   zl,ST23
		ld   ST21,Z  
		mov   zl,TMP1
		ld   ST22,Z  
		mov   zl,TMP2
		ld   ST23,Z  
# row 3
		mov   zl,ST32
		ld   ST33,Z  
		mov   zl,ST31
		ld   ST32,Z  
		mov   zl,ST30
		ld   ST31,Z  
		mov   zl,TMP3
		ld   ST30,Z  
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
100:
#AddRoundKey
		ld   TMP4,XKEYPTR+
		eor  ST00,TMP4
		ld   TMP0,XKEYPTR+
		eor  TMP0,ST10
		ld   TMP1,XKEYPTR+
		eor  TMP1,ST20
		ld   TMP4,XKEYPTR+
		eor  ST30,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST01,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST11,TMP4
		ld   TMP2,XKEYPTR+
		eor  TMP2,ST21
		ld   TMP4,XKEYPTR+
		eor  ST31,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST02,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST12,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST22,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST32,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST03,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST13,TMP4
		ld   TMP4,XKEYPTR+
		eor  ST23,TMP4
		ld   TMP3,XKEYPTR+
		eor  TMP3,ST33
		dec  ROUNDS
		breq 1f ; exit
		rjmp 101b
1:
#SubBytesShiftRows
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
		mov   zl,ST11
		ld   ST10,Z  
		mov   zl,ST12
		ld   ST11,Z  
		mov   zl,ST13
		ld   ST12,Z  
		mov   zl,TMP0
		ld   ST13,Z  
# row 2
		mov   zl,ST22
		ld   ST20,Z  
		mov   zl,ST23
		ld   ST21,Z  
		mov   zl,TMP1
		ld   ST22,Z  
		mov   zl,TMP2
		ld   ST23,Z  
# row 3
		mov   zl,ST32
		ld   ST33,Z  
		mov   zl,ST31
		ld   ST32,Z  
		mov   zl,ST30
		ld   ST31,Z  
		mov   zl,TMP3
		ld   ST30,Z  
#AddRoundKey
		ld   TMP0,XKEYPTR+
		eor  ST00,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST10,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST20,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST30,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST01,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST11,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST21,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST31,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST02,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST12,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST22,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST32,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST03,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST13,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST23,TMP0
		ld   TMP0,XKEYPTR+
		eor  ST33,TMP0
#-------------- Real function ends here --------------
#ifdef AES_BENCHMARK
AES_Encrypt_R_end1:
		.global AES_Encrypt_R_end1
		lds  r24,_SFR_MEM_ADDR(TCNT1L)
		sts  benchmark_data+4,r24
		lds  r24,_SFR_MEM_ADDR(TCNT1H)
		sts  benchmark_data+5,r24
#endif
		movw XKEYPTR_L,OUTADDR_L
#Store16_Data
		st   XKEYPTR+,ST00
		st   XKEYPTR+,ST10
		st   XKEYPTR+,ST20
		st   XKEYPTR+,ST30
		st   XKEYPTR+,ST01
		st   XKEYPTR+,ST11
		st   XKEYPTR+,ST21
		st   XKEYPTR+,ST31
		st   XKEYPTR+,ST02
		st   XKEYPTR+,ST12
		st   XKEYPTR+,ST22
		st   XKEYPTR+,ST32
		st   XKEYPTR+,ST03
		st   XKEYPTR+,ST13
		st   XKEYPTR+,ST23
		st   XKEYPTR+,ST33
		pop  TMP4
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
AES_Encrypt_R_end:
		.global AES_Encrypt_R_end
#endif

		.size AES_Encrypt_R,.-AES_Encrypt_R

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
