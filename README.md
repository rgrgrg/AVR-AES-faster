# AVR-AES-faster
Fast AES library for 8-bit AVR processors
1. Constant-time operation
2. Created from scratch using description from FIPS 197 
2. Only S-Box and InvSbox tables (512 bytes) 
3. Ability to calculate round keys on fly to save RAM (16 bytes RAM required for temporary key, can be "rolled back" after use) for AES128
4. No need fo InvMixColumn step for round keys (faster decryption, same keys for encryption and decryption)

## Test results
All times in clock cycles
### NORMAL (Version with precomputed keys)
Requires RAM for precomputing all round keys
Encryption:
* AES128, FLASH S-Box: 2111
* AES128, RAM S-Box: 1951  
* AES192, FLASH S-Box: 2543
* AES192, RAM S-Box: 2351 
* AES256, FLASH S-box: 2975
* AES256, RAM S-box: 2751

Decryption:
* AES128, FLASH S-Box: 2682
* AES128, RAM S-Box: 2522
* AES192, FLASH S-Box: 3242
* AES192, RAM S-Box: 3050
* AES256, FLASH S-box: 3802
* AES256, RAM S-box: 3578

Expanding key to round keys:
* AES128, FLASH S-Box: 748 c
* AES128, RAM S-Box: 708 
* AES192, FLASH S-Box: 807 
* AES192, RAM S-Box: 775
* AES256, FLASH S-box: 2044
* AES256, RAM S-box: 1992


### TINY (version with small ram requirements)
Computes key on the fly
Encryption: 2949
Decryption: 3538
* Generating key for decryption/roll-back after decryption: 405
* Rolling-back key after encryption: 423

