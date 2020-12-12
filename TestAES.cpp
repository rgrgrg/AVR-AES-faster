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
#include "TestAES.h"

typedef uint8_t AESState [4][4];
typedef uint8_t AESKeyWord[4];
typedef AESKeyWord AESKey[4 * (16 + 1)]; //Max size for AES256

// Bit rotations
static inline uint8_t rol(uint8_t x,uint8_t n)
{
    return (x<<n) | (x>> (8-n));
}


static inline uint8_t ror(uint8_t x,uint8_t n)
{
    return (x>>n) | (x<<(8-n));
}

// Galois Field GF(2**8) operations
static uint8_t GMul(uint8_t x, uint8_t y)
{
    uint8_t sum = 0;
    while (y)
    {
	if ( y & 1)
	    sum ^= x;
	x = (x << 1) ^ ((x & 0x80) ?  0x1b : 0);
	y >>= 1;
    }
    return sum;
}


//Russian peasant algorithm
static uint8_t GPwr(uint8_t a,uint8_t b)
{
    uint8_t res = 1;
    while (b)
    {
	if (b & 1)
	    res = GMul( res,a);
	if (b>>=1)
	a=GMul(a,a);
    }
    return res;
}

static uint8_t GModInv(uint8_t x)
{
    if (!x)
	return 0; //FIPS 197
    // According to Wikipedia in GF(2**n): modInv(x)=x**(2**n-2)
    return GPwr(x,254); 
}

//============================= AES Primitives ==============================

// FIPS 197 section 5.2
static uint8_t Rcon(uint8_t x)
{
    return GPwr(2,x-1);
}

// FIPS 197 equation 5.1
static uint8_t SBox(uint8_t x)
{
    x=GModInv(x);
    return x ^ ror(x,4) ^ ror(x,5) ^ ror(x,6) ^ ror(x,7) ^ 0x63;
}

// Multiplication by inverse matrix (to equation 5.2)
static uint8_t InvSBox(uint8_t x)
{
    x ^= 0x63;
    return GModInv(ror(x,2) ^ ror(x,5) ^ ror(x,7));
}

//=============================== AES Steps =================================
// FIPS 197 5.1.1
static void SubBytes(AESState &state)
{
    uint8_t x, y;
    for (y = 0; y < 4; y++)
	for (x = 0; x < 4; x++)
	    state[y][x] = SBox(state[y][x]);
}

// FIPS 197 5.3.2
static void InvSubBytes(AESState &state)
{
    uint8_t x, y;
    for (y = 0; y < 4; y++)
	for (x = 0; x < 4; x++)
	    state[y][x] = InvSBox(state[y][x]);
}


// FIPS 197 5.1.2
static void ShiftRows(AESState &state)
{
    int8_t x;
    uint8_t t;

    t = state[1][0];
    for (x = 0; x < 3; x++)
	state[1][x] = state [1][x + 1];
    state[1][3] = t;

    for (x = 0; x < 2; x++)
    {
	t              = state[2][x + 0];
	state[2][x + 0] = state[2][x + 2];
	state[2][x + 2] = t;
    }

    t = state[3][3];
    for (x = 3; x > 0; x--)
	state[3][x] = state [3][x - 1];
    state[3][0] = t;
}

//FIPS 197 5.3.1
static void InvShiftRows(AESState &state)
{
    int8_t x;
    uint8_t t;

    t = state[1][3];
    for (x = 3; x > 0; x--)
	state[1][x] = state [1][x - 1];
    state[1][0] = t;

    for (x = 0; x < 2; x++)
    {
	t               = state[2][x + 0];
	state[2][x + 0] = state[2][x + 2];
	state[2][x + 2] = t;
    }

    t = state[3][0];
    for (x = 0; x < 3; x++)
	state[3][x] = state [3][x + 1];
    state[3][3] = t;
}


//Internal function FIPS 197 5.1.3 and 5.3.3
static void MixColumnsInt(AESState &state, const uint8_t *coeff)
{
    uint8_t ncol[4];
    uint8_t x, y, i;
    for (x = 0; x < 4; x++)
    {
	for (y = 0; y < 4; y++)
	{
	    ncol[y] = 0;
	    for (i = 0; i < 4; i++)
		ncol[y] ^= GMul(state[i][x], coeff[(i + 4 - y) % 4]);
	}
	for (y = 0; y < 4; y++)
	    state[y][x] = ncol[y];
    }
}

//FIPS 197 5.1.3
static const uint8_t mix_coeff[4] = {2, 3, 1, 1};
static void MixColumns(AESState &state)
{
    MixColumnsInt(state, mix_coeff);
}

//FIPS 197 5.3.3
static const uint8_t inv_mix_coeff[4] = {0x0e, 0x0b, 0x0d, 0x09};
static void InvMixColumns(AESState &state)
{
    MixColumnsInt(state, inv_mix_coeff);
}


//FIPS 197 5.1.4 (also 5.3.4)
static void AddRoundKey(AESState &state, const AESKey &rk, uint8_t i0)
{
    uint8_t x, y;
    for (y = 0; y < 4; y++)
	for (x = 0; x < 4; x++)
	    state[y][x] ^= rk[x + i0][y];
}


//FIPS 197 5.2
static void SubWord(AESKeyWord &w)
{
    uint8_t i;
    for (i = 0; i < 4; i++)
	w[i] = SBox(  w[i] );
}

//FIPS 197 5.2
static void RotWord(AESKeyWord &w)
{
    uint8_t t, i;
    t = w[0];
    for (i = 0; i < 3; i++)
	w[i] = w[i + 1];
    w[3] = t;
}


//============================== AES Operations =============================
// Key Expansion - FIPS 197 5.2
static void KeyExpansion(const uint8_t *k0, AESKey &rk, uint8_t nk, uint8_t nr)
{
    int x, y;
    for (y = 0; y < nk; y++)
    {
	for (x = 0; x < 4; x++)
	rk[y][x] = *k0++;
    }

    uint8_t i = nk;
    while (i < 4 * (nr + 1) )
    {
	AESKeyWord temp;
	for (int x = 0; x < 4; x++)
	    temp[x] = rk[i - 1][x];

	if ( i % nk == 0)
	{
	    RotWord(temp);
	    SubWord(temp);
	    temp[0] ^= Rcon( i / nk ); 
	}
	else if ( (nk > 6) &&  ( i % nk == 4) )
	    SubWord(temp);

	for (x = 0; x < 4; x++)
	    rk[i][x] = rk[i - nk][x] ^  temp[x];
	i += 1;
    }
}

// Key Expansion for Equivalent Inverse Algorithm - FIPS 5.3.5 (Fig 15)
static void KeyExpansionInv(const uint8_t *k0, AESKey &rk, uint8_t nk, 
	uint8_t nr)
{
    KeyExpansion(k0, rk, nk, nr);

    uint8_t i;
    for (i = 1; i < nr; i++)
    {
	AESState tmp;
	uint8_t x, y;

	for (x = 0; x < 4; x++)
	    for (y = 0; y < 4; y++)
		tmp[y][x] = rk[i * 4 + x][y];

	InvMixColumns(tmp);

	for (x = 0; x < 4; x++)
	    for (y = 0; y < 4; y++)
		rk[i * 4 + x][y] = tmp[y][x];
    }
}



//Encryption - FIPS 197 5.1
static void Encrypt( AESState &state, const AESKey &key, uint8_t nr)
{
    int8_t r;
    AddRoundKey(state, key, 0);
    for (r = 1; r < nr; r++)
    {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key, 4 * r);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key, 4 * nr);
}

//Decryption using Inverse AES - FIPS 5.3
static void DecryptInv( AESState &state, const AESKey &key, uint8_t nr)
{
    int8_t r;
    AddRoundKey(state, key, 4 * nr);
    for (r = nr - 1; r > 0; r--)
    {
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, key, 4 * r);
	InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, key, 0);
}

//Decryption using Eguivalent Inverse Algorithm - FIPS 5.3.5
static void DecryptEqu( AESState &state, const AESKey &key, uint8_t nr)
{
    int8_t r;
    AddRoundKey(state, key, 4 * nr);
    for (r = nr - 1; r > 0; r--)
    {
	InvSubBytes(state);
	InvShiftRows(state);
	InvMixColumns(state);
	AddRoundKey(state, key, 4 * r);
    }
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, key, 0);
}





//===================== Interface to cruel outside world ======================

static void load_state(AESState &state,const uint8_t *in)
{
    uint8_t x, y;
    for (x = 0; x < 4; x++)
	for (y = 0; y < 4; y++)
	    state[y][x] = *in++;
}

static void save_state(const AESState &state,uint8_t *out)    
{
    uint8_t x, y;
    for (x = 0; x < 4; x++)
	for (y = 0; y < 4; y++)
	    *out++ = state[y][x];
}

// Key Expansion - FIPS 197 5.2
void TestAES_ExpandKey(const uint8_t *key, uint8_t *xkey, 
	uint8_t nk, uint8_t nr)
{
    KeyExpansion(key, *((AESKey *)xkey), nk, nr);
}

// Key Expansion for Equivalent Inverse Algorithm - FIPS 5.3.5 (Fig 15)
void TestAES_ExpandKeyInv(const uint8_t *key, uint8_t *xkey, 
	uint8_t nk, uint8_t nr)
{
    KeyExpansionInv(key, *((AESKey *)xkey), nk, nr);
}


//Encryption - FIPS 197 5.1
void TestAES_Encrypt( const uint8_t *in, uint8_t *out, const uint8_t *xkey, 
	uint8_t nr)
{
    AESState state;

    load_state(state,in);
    Encrypt(state,*((AESKey *)xkey),nr);
    save_state(state,out);
}

//Decryption using Inverse AES - FIPS 5.3
void TestAES_DecryptInv( const uint8_t *in, uint8_t *out, const uint8_t *xkey, 
	uint8_t nr)
{
    AESState state;

    load_state(state,in);
    DecryptInv(state,*((AESKey *)xkey),nr);
    save_state(state,out);
}

//Decryption using Eguivalent Inverse Algorithm - FIPS 5.3.5
void TestAES_DecryptEqu( const uint8_t *in, uint8_t *out, const uint8_t *xkey, 
	uint8_t nr)
{
    AESState state;

    load_state(state,in);
    DecryptEqu(state,*((AESKey *)xkey),nr);
    save_state(state,out);
}

