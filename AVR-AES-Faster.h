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
#ifndef AVR_AES_FASTER_H_INCLUDED
#define AVR_AES_FASTER_H_INCLUDED
#include <stdint.h>

// AES Key table sizes (see FIPS 197 for details)
#define AES128_Nk  4
#define AES192_Nk  6
#define AES256_Nk  8

// Number of rounds for different key sizes
#define AES128_Nr 10
#define AES192_Nr 12
#define AES256_Nr 14

//Block size
#define AES_BLOCKSIZE 16
#define AES128_BLOCKSIZE AES_BLOCKSIZE
#define AES192_BLOCKSIZE AES_BLOCKSIZE
#define AES256_BLOCKSIZE AES_BLOCKSIZE

//Key size
#define AES128_KEYSIZE (AES128_Nk*4)
#define AES192_KEYSIZE (AES192_Nk*4)
#define AES256_KEYSIZE (AES256_Nk*4)

//Round key size
#define AES_RKEYSIZE AES_BLOCKSIZE

//Expanded key
#define AES128_XKEYSIZE ((AES128_Nr+1)*AES_RKEYSIZE)
#define AES192_XKEYSIZE ((AES192_Nr+1)*AES_RKEYSIZE)
#define AES256_XKEYSIZE ((AES256_Nr+1)*AES_RKEYSIZE)

#ifdef __cplusplus
extern "C" {
#endif
    // Built-in AES boxes
    extern const uint8_t AES_SBox_F   [256];
    extern const uint8_t AES_InvSBox_F[256];

    // You have to define this variable in your program
    extern uint8_t AES_SBox_R   [256]   __attribute__ ((aligned (256)));
    extern uint8_t AES_InvSBox_R[256]   __attribute__ ((aligned (256)));

    //Standard version
    extern void AES_Encrypt_F(const void *in, void *out, const void *xkey, 
	    uint8_t nr);

    extern void AES_Decrypt_F(const void *in, void *out, const void *xkey, 
	    uint8_t nr);
    extern void AES_Decrypt128_F(const void *in, void *out, const void *xkey);
    extern void AES_Decrypt192_F(const void *in, void *out, const void *xkey);
    extern void AES_Decrypt256_F(const void *in, void *out, const void *xkey);

    extern void AES_ExpandKey128_F(const void *keyin, void *xkeyout);

    extern void AES_ExpandKey192_F(const void *keyin, void *xkeyout);
  
    extern void AES_ExpandKey_F(const void *keyin, void *xkeyout, 
	    uint8_t nk, uint8_t nr);


    extern void AES_Encrypt_R(const void *in, void *out, const void *xkey, 
	    uint8_t nr);

    extern void AES_Decrypt_R(const void *in, void *out, const void *xkey, 
	    uint8_t nr);
    extern void AES_Decrypt128_R(const void *in, void *out, const void *xkey);
    extern void AES_Decrypt192_R(const void *in, void *out, const void *xkey);
    extern void AES_Decrypt256_R(const void *in, void *out, const void *xkey);

    extern void AES_ExpandKey128_R(const void *keyin, void *xkeyout);

    extern void AES_ExpandKey192_R(const void *keyin, void *xkeyout);

    extern void AES_ExpandKey_R(const void *keyin, void *xkeyout, 
	    uint8_t nk, uint8_t nr);

    //Tiny version
    extern void AES_Encrypt128_T(const void *in, void *out, void *key0);
    
    extern void AES_Decrypt128_T(const void *in, void *out, void *key10);
    
    extern void AES_ExpandLastKey128_T (const void *key0in, void *key10out);
    
    extern void AES_ExpandFirstKey128_T(const void *key10in, void *key0out);
  //#endif
#ifdef __cplusplus
};
#endif

// constant size Encrypt
inline void AES_Encrypt128_F(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_F(in,out,xkey, AES128_Nr);
}

inline void AES_Encrypt192_F(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_F(in,out,xkey, AES192_Nr);
}

inline void AES_Encrypt256_F(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_F(in,out,xkey, AES256_Nr);
}


inline void AES_Encrypt128_R(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_R(in,out,xkey, AES128_Nr);
}

inline void AES_Encrypt192_R(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_R(in,out,xkey, AES192_Nr);
}

inline void AES_Encrypt256_R(const void *in, void *out, const void *xkey)
{
    AES_Encrypt_R(in,out,xkey, AES256_Nr);
}

// constant size ExpandKey
inline void AES_ExpandKey256_F(const void *keyin, void *xkeyout)
{
    AES_ExpandKey_F(keyin,xkeyout, AES256_Nk, AES256_Nr);
}

inline void AES_ExpandKey256_R(const void *keyin, void *xkeyout)
{
    AES_ExpandKey_R(keyin,xkeyout, AES256_Nk, AES256_Nr);
}

#endif
