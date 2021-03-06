# AVR-AES-faster
Fast AES library for 8-bit AVR processors
1. Constant-time operation
2. Created from scratch using description from FIPS 197 
2. Only S-Box and InvSbox tables (512 bytes) 
3. Ability to calculate round keys on fly to save RAM (16 bytes RAM required for temporary key, can be "rolled back" after use) for AES128
4. Decryption uses *Inverse Cipher*, not *Equivalent Inverse Cipher* - no need for InvMixColumn step for round keys (faster operation, same intermediate keys for encryption and decryption)
5. Seems to be faster than:
   1. ["AVRAES: The AES block cipher on AVR controllers" (aka rijndaelfast.asm)](http://point-at-infinity.org/avraes/)
   2. ["Fast Software AES Encryption"](https://cseweb.ucsd.edu/~dstefan/pubs/osvik:2010:fast.pdf)
   3. ["AVR CryptoLib"](http://www.emsign.nl/)
   4. ["AVR-Crypto-Lib"](https://wiki.das-labor.org/w/AVR-Crypto-Lib/en#Blockchiphers)
   5. ["Implementations of low cost block ciphers in Atmel AVR devices."](https://perso.uclouvain.be/fstandae/source_codes/lightweight_ciphers/) (*tiny* version)
   6. Any pure C/C++ implementation
6. Test sketch with example vectors from FIPS 197 for Arduino Uno and independent pure C implementation for self check.
   
## Speedtest results
All times in clock cycles for "pure" inline version (no rcall/ret, all arguments loaded to registers). 
When interfacing with other code, additional time will be needed to setup registers etc. (interfacing with 
C ABI takes about 140 cycles per block for encryption/decryption *on callee side*).

### Normal (Version with precomputed keys)
Requires 176/208/240 bytes RAM for precomputing all round keys (can be done in place)

*RAM* version keeps SBox and invSBox in RAM instead of flash for faster lookups

Key Size| S-Box | Encryption time | Decryption time | Key Expansion time | S-box_invSBox initialization
--------|-------|-----------------|-----------------|--------------------|---------------------
128     | Flash |         **2111**|         **2687**|               748  |                   0
128     | RAM   |             1951|             2527|               708  |               8076*
192     | Flash |             2543|             3247|               807  |                   0
192     | RAM   |             2351|             3055|               775  |               8076*
256     | Flash |             2975|             3807|              2044  |                   0
256     | RAM   |             2751|             3583|              1992  |               8076*

\* You can also copy tables from flash, see examples

### Tiny (128-bit version with small RAM requirements)
Computes keys on the fly
Key Size| S-Box | Encryption time | Decryption time | Key Expansion time
--------|-------|-----------------|-----------------|-------------------
128     | Flash | 2949            | 3538            |405/423

**Both encryption and decryption modify key im memory. The key must be overwritten with correct value or rolled back before next operation.**

Decryption after encryption (or vice versa) does not need key modification.
   

## Code size

Pure assembler version, inlined, all input parameters set, in place key expansion.

### Totals

Variant       | Key size | Bytes Flash | Bytes RAM | Bytes on stack
--------------|----------|-------------|-----------|---------------
Flash         | 128      | 1610        | 176       | 0
RAM           | 128      | **1236**    | 688       | 0
Tiny (Flash)  | 128      | 2012        | **16**    | 0
Flash         | 192      | 1644        | 208       | 0
RAM           | 192      | 1270        | 720       | 0
Flash         | 256*     | 1648        | 240       | 0
RAM           | 256*     | 1274        | 752       | 0

\* 256-bit version can also be used for other key sizes.

### By Function
Variant       | Operation         | Key size | Bytes
--------------|-------------------|----------|---------
Flash/RAM     | Encryption        | Any      | 404
Flash/RAM     | Decryption        | Any      | 596
Flash/RAM     | Key Expansion     | Any      | 136
Flash/RAM     | Key Expansion     | 128      | 98
Flash/RAM     | Key Expansion     | 192      | 132
RAM           | Init SBox         | Any      | 124
RAM           | Init InvSBox      | Any      | 124
RAM           | Init SBox+InvSBox | Any      | 138
Tiny (Flash)  | Encryption        | 128      | 510
Tiny (Flash)  | Decryption        | 128      | 798 
Tiny (Flash)  | Rewind K0->K10    | 128      | 96
Tiny (Flash)  | Rewind K10->K0    | 128      | 96

All functions can be inlined.

Lookup tables:
Table  | Size | Alignment
-------| -----|----------
SBox   |256   | 256
InvSBox|256   | 256     

## How to use C/C++ version

**Remember: [Use cryptography correctly](https://cybersecurity.ieee.org/blog/2015/11/13/use-cryptography-correctly/).**

### Flash version
Required variables:
```c++
uint8_t key [AES128_KEYSIZE];   //encryption key
uint8_t xkey[AES128_XKEYSIZE]; //precomputed round keys
uint8_t plaintext [AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 
```

One-time (per key) initialization:
```c++
AES_ExpandKey128_F(&key[0], &xtest[0]);
```

Encryption:
```c++
AES_Encrypt128_F(&plaintext[0], &ciphertext[0], &xkey[0]);
```

Decryption:
```c++
AES_Decrypt128_F(&ciphertext[0], &plaintext[0], &xkey[0]);
```

### RAM version
Required variables:
```c++
uint8_t AES_SBox_R   [256];  // SBox - must be global
uint8_t AES_InvSBox_R[256]; // InvSBox - must be global

uint8_t key [AES128_KEYSIZE];   //encryption key
uint8_t xkey[AES128_XKEYSIZE]; //precomputed round keys
uint8_t plaintext [AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 
```

One time initialization (global):
* Fastest method, requires 512B flash for tables
```c++
memcpy_P(AES_SBox_R   , AES_SBox_F   , sizeof(AES_SBox_R   ));
memcpy_P(AES_InvSBox_R, AES_InvSBox_F, sizeof(AES_InvSBox_R));
```
* Initializing both table at once:
```c++
AES_InitSBoxInvSBox_R();
```
* Initializing one table at tme:
```c++
AES_InitSBox_R();    //Needed for encryption and key expansion
AES_InitInvSBox_R(); //Needed for decryption
```

One time (per-key) initialization:
```c++
AES_ExpandKey128_R(&key[0], &xtest[0]);
```

Encryption:
```c++
AES_Encrypt128_R(&plaintext[0], &ciphertext[0], &xkey[0]);
```

Decryption:
```c++
AES_Decrypt128_R(&ciphertext[0], &plaintext[0], &xkey[0]);
```

### Tiny version
Uses 48 bytes per key.

Required variables:
```c++
uint8_t key   [AES128_KEYSIZE];    //encryption key
uint8_t dkey  [AES128_KEYSIZE];   //decryption key
uint8_t tmpkey[AES128_KEYSIZE];  //working copy

uint8_t plaintext [AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 
```

One time (per-key) initialization:
```c++
AES_ExpandLastKey128_T(&key[0], &dkey[0]);
```

Encryption (each block):
```c++
memcpy(&tmpkey[0],&key[0],sizeof(tmpkey));
AES_Encrypt128_T(&plaintext[0], &ciphertext[0], &tmpkey[0]);
```

Decryption (each block):
```c++
memcpy(&tmpkey[0],&dkey[0],sizeof(tmpkey));
AES_Decrypt128_T(&ciphertext[0], &plaintext[0], &tmpkey[0]);
```

### Tiny version (minimal RAM usage)
Uses 16 bytes per key.

Required variables:
```c++
uint8_t key   [AES128_KEYSIZE];    //encryption key

uint8_t plaintext [AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 
```


Encryption (each block):
```c++
AES_Encrypt128_T(&plaintext[0], &ciphertext[0], &key[0]);
AES_ExpandFirstKey128_T(&key[0], &key[0]);
```

Decryption (each block):
```c++
AES_ExpandLastKey128_T(&key[0], &key[0]);
AES_Decrypt128_T(&ciphertext[0], &plaintext[0], &key[0]);
```

Notes: 
1. `AES_ExpandLastKey128_T` is inverse of `AES_ExpandFirstKey128_T`
2. `AES_Encrypt128_T` transforms key to same form as `AES_ExpandLastKey128_T` (i.e. last round key)
3. `AES_Decrypt128_T` transforms key to same form as `AES_ExpandFirstKey128_T` (i.e. original key, used in first round)

------------------------------------------------------------------------------------------------------------

## TODO
- [x] *Flash* version.
- [x] Make it faster and smaller.
- [x] *RAM* version (slightly faster but requiring 512B of precious RAM). 
- [x] *Tiny* version (on fly key generation, low RAM requirements).
- [x] Make tiny version smaller (remove duplicate code at expense of few cycles)
- [x] Generate S-Boxes for RAM version instead of copying Flash
- [ ] *Nano* version (like tiny, without tables, size optimized, much slower).
- [ ] Test against [more test vectors](https://www.cosic.esat.kuleuven.be/nessie/testvectors/).


