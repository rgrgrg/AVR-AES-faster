/*#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#
#                                                                           #
#    AVR-AES-Faster Library                                                 #
#    (c) 2020 Radosław Gancarz <radgan99@gmail.com>                         #
#                                                                           #
#    This Source Code Form is subject to the terms of the Mozilla Public    #
#    License, v. 2.0. If a copy of the MPL was not distributed with this    #
#    file, You can obtain one at http://mozilla.org/MPL/2.0/.               #
#                                                                           #
#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#*/

/****************************************************************************
*                                                                           *
*  Pure C implementation of Advanced Encryption Standard with on fly S-Box  *
*   FOR TEST PURPOSES ONLY - DIRTY, SLOW, SUSCEPTIBLE TO TIMING ATTACKS     *
*                                                                           *
****************************************************************************/
#ifndef TESTAES_H_INCLUDED
#define TESTAES_H_INCLUDED
#include <stdint.h>

extern void TestAES_ExpandKey(const uint8_t *key, uint8_t *xkey, 
	uint8_t nk, uint8_t nr);

extern void TestAES_ExpandKeyInv(const uint8_t *key, uint8_t *xkey, 
	uint8_t nk, uint8_t nr);

extern void TestAES_Encrypt( const uint8_t *in, uint8_t *out, 
	const uint8_t *xkey, uint8_t nr);

extern void TestAES_DecryptInv( const uint8_t *in, uint8_t *out, 
	const uint8_t *xkey, uint8_t nr);

extern void TestAES_DecryptEqu( const uint8_t *in, uint8_t *out, 
	const uint8_t *xkey, uint8_t nr);

#endif
