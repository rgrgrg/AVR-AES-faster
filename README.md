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
Requires RAM for precomputing all round keys (176/208/272 bytes)
Key Size| S-Box | Encryption time | Decryption time | Key Expansion time
--------|-------|-----------------|-----------------|--------------------
128     | Flash |             2111|             2682|               748
128     | RAM   |             1951|             2522|               708 
192     | Flash |             2543|             3242|               807 
192     | RAM   |             2351|             3050|               775
256     | FLASH |             2975|             3802|              2044
256     | RAM   |             2751|             3578|              1992

### TINY (version with small ram requirements)
AES128 only
Computes keys on the fly

Encryption: 2949

Decryption: 3538

* Generating key for decryption/roll-back after decryption: 405
* Rolling-back key after encryption: 423

