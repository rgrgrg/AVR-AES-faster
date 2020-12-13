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
   
## Speedtest results
All times in clock cycles for inline version (no rcall/ret)
### NORMAL (Version with precomputed keys)
Requires 176/208/240 bytes RAM for precomputing all round keys (can be done in place)

*RAM* version keeps SBox and invSBox in RAM instead of flash for faster lookups

Key Size| S-Box | Encryption time | Decryption time | Key Expansion time
--------|-------|-----------------|-----------------|--------------------
128     | Flash |         **2111**|         **2682**|               748
128     | RAM   |             1951|             2522|               708 
192     | Flash |             2543|             3242|               807 
192     | RAM   |             2351|             3050|               775
256     | FLASH |             2975|             3802|              2044
256     | RAM   |             2751|             3578|              1992

### TINY (128-bit version with small RAM requirements)
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
Flash         | 128      | 1738        | 176       | 0
RAM           | 128      | 1738        | 688       | 0
Tiny (Flash)  | 128      | 2158        | **16**    | 0
Flash         | 192      | 1772        | 208       | 0
RAM           | 192      | 1772        | 720       | 0
Flash         | 256*     | 1776        | 240       | 0
RAM           | 256*     | 1776        | 752       | 0

* 256-bit version can also be used for other key sizes

### By Function
Variant       | Operation     | Key size | Bytes
--------------|---------------|----------|---------
Flash/RAM     | Encryption    | Any      | 468
Flash/RAM     | Decryption    | Any      | 660
Flash/RAM     | Key Expansion | Any      | 136
Flash/RAM     | Key Expansion | 128      | 98
Flash/RAM     | Key Expansion | 192      | 132
Tiny (Flash)  | Encryption    | 128      | 582
Tiny (Flash)  | Decryption    | 128      | 872 
Tiny (Flash)  | Rewind K0->K10| 128      | 96
Tiny (Flash)  | Rewind K10->K0| 128      | 96

All functions can be inlined.

Lookup tables:
Table  | Size | Alignment
-------| -----|----------
SBox   |256   | 256
InvSBox|256   | 256     

## How to use

### Flash version

```cplusplus
uint8_t key[AES128_KEYSIZE];   //encryption key
uint8_t xkey[AES128_XKEYSIZE]; //precomputed round keys
uint8_t plaintext[AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 

//One time (per key) initialization
AES_ExpandKey128_F(&key[0], &xtest[0]);

//Encryption
AES_Encrypt128_F(&plaintext[0], &ciphertext[0], &xkey[0]);

//Decryption
AES_Decrypt128_F(&ciphertext[0], &plaintext[0], &xkey[0]);
```

### RAM version
```cplusplus
uint8_t AES_SBox_R   [256]; // SBox - must be global
uint8_t AES_InvSBox_R[256]; // InvSBox - must be global

uint8_t key[AES128_KEYSIZE];   //encryption key
uint8_t xkey[AES128_XKEYSIZE]; //precomputed round keys
uint8_t plaintext[AES_BLOCKSIZE]; 
uint8_t ciphertext[AES_BLOCKSIZE]; 

//One time initialization
memcpy_P(AES_SBox_R   , AES_SBox_F   , sizeof(AES_SBox_R   ));
memcpy_P(AES_InvSBox_R, AES_InvSBox_F, sizeof(AES_InvSBox_R));

//One time (per-key) initialization
AES_ExpandKey128_F(&key[0], &xtest[0]);

//Encryption
AES_Encrypt128_F(&plaintext[0], &ciphertext[0], &xkey[0]);

//Decryption
AES_Decrypt128_F(&ciphertext[0], &plaintext[0], &xkey[0]);
```

### Tiny version

### Tiny version (minimal RAM usage)




