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

#include <avr/pgmspace.h>
#include <stdio.h>
#include "AVR-AES-Faster.h"
#include "AVR-AES-Faster-devel.h"
#include "TestAES.h"

#define TEST_RAM

//FIPS 197 Appendix C Example Vectors
const uint8_t FIPS_ExCXXX_P[] PROGMEM = { 
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //Plaintext
  
const uint8_t FIPS_ExCXXX_K[] PROGMEM = { 
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f }; //Key
  
const uint8_t FIPS_ExC128_C[] PROGMEM = { 
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }; //ciphertext
  
const uint8_t FIPS_ExC128_L[] PROGMEM = { 
  0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17, 
  0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5 }; //Last round key
  

const uint8_t FIPS_ExC192_C[] PROGMEM = { 
  0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 
  0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
  
const uint8_t FIPS_ExC192_L[] PROGMEM = { 
  0xa4, 0x97, 0x0a, 0x33, 0x1a, 0x78, 0xdc, 0x09, 
  0xc4, 0x18, 0xc2, 0x71, 0xe3, 0xa4, 0x1d, 0x5d };
  

const uint8_t FIPS_ExC256_C[] PROGMEM = { 
  0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 
  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
  
const uint8_t FIPS_ExC256_L[] PROGMEM = { 
  0x24, 0xfc, 0x79, 0xcc, 0xbf, 0x09, 0x79, 0xe9, 
  0x37, 0x1a, 0xc2, 0x3c, 0x6d, 0x68, 0xde, 0x36 };
  

//FIPP 197 Appendix B Example Vector
const uint8_t FIPS_ExB128_P[] PROGMEM = { 
  0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 }; //plaintext
  
const uint8_t FIPS_ExB128_K[] PROGMEM = { 
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }; //key
  
const uint8_t FIPS_ExB128_C[] PROGMEM = { 
  0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 
  0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 }; //ciphertext
  
const uint8_t FIPS_ExB128_L[] PROGMEM = { 
  0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 
  0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6 }; // Last round key
  

typedef struct
{
  uint8_t nk;
  uint8_t nr;
  const uint8_t *plaintext, *ciphertext, *key, *lastkey;
} test_vector_t;

//Table listing all test vectors

const test_vector_t test_vectors[] PROGMEM = {
  { AES128_Nk, AES128_Nr, FIPS_ExB128_P, FIPS_ExB128_C, FIPS_ExB128_K, FIPS_ExB128_L },
  { AES128_Nk, AES128_Nr, FIPS_ExCXXX_P, FIPS_ExC128_C, FIPS_ExCXXX_K, FIPS_ExC128_L },
  { AES192_Nk, AES192_Nr, FIPS_ExCXXX_P, FIPS_ExC192_C, FIPS_ExCXXX_K, FIPS_ExC192_L },
  { AES256_Nk, AES256_Nr, FIPS_ExCXXX_P, FIPS_ExC256_C, FIPS_ExCXXX_K, FIPS_ExC256_L }
};

#ifdef AES_BENCHMARK
extern "C" {
  extern const void *benchmark_sizes[];
}

uint16_t benchmark_data[4];
void print_sizes()
{
  char buf[24];
  printf_P(PSTR("# Function sizes\n\n"
                "Function name          | asm | abi | +abi\n"
                "-----------------------|-----|-----|-----\n"));
  const void **p;
  p=&benchmark_sizes[0];
  while (true)
  {
    const char *   fname = (const char *)pgm_read_ptr(p++);
    if (!fname)
      return;

    uint16_t cstart = pgm_read_word(p++);
    uint16_t astart = pgm_read_word(p++);
    uint16_t aend   = pgm_read_word(p++);
    uint16_t cend   = pgm_read_word(p++);
    uint16_t asize  = aend - astart;
    // Overhead for time measurements AES_BENCHMARK: 
    // 4 bytes for lds, 4 bytes for sts, always in pairs, 4 times per function
    uint16_t csize = cend - cstart - (4 + 4) * 2 * 4;

    strncpy_P(&buf[0],fname,sizeof(buf));
    printf_P(PSTR("%23s|%5d|%5d|%5d\n"), 
	       buf, asize, csize, csize - asize);

  }
}


void print_cycles(uint16_t wrapped_params)
{
  //One measurement takes 8 cycles
  //rcall + return takes  8 cycles
  uint16_t asmtime = benchmark_data[2] - benchmark_data[1] - 8*1;
  uint16_t alltime = benchmark_data[3] - benchmark_data[0] - 8*3+8;
  alltime+=wrapped_params; // Any parameter from inline function takes 
                           // one clock cycle (ldi)
  printf_P(PSTR(" asm=%4d, with_abi=%4d +abi=%3d\n"),
		 asmtime,  alltime, alltime-asmtime);
}

#endif


#define TEST_MAGIC 0x5a
bool test_expansion()
{
  uint8_t testblock[AES_BLOCKSIZE];
  uint8_t key  [AES256_KEYSIZE];
  uint8_t xkey [AES256_XKEYSIZE + 16];
  uint8_t xtest[AES256_XKEYSIZE + 16];
  char    fname_buf[24];
  uint8_t nk, nr;
  uint8_t n = sizeof(test_vectors) / sizeof(test_vectors[0]);
  const uint8_t *ptr;

  printf_P(PSTR("< << <<< <<<< <<<<< <<<<<< <<< KEY EXPANSION >>> >>>>>> >>>>> >>>> >>> >> >\n\n"));
  bool ok = true;
  for (uint8_t i = 0; i < n; i++)
  {
    nk = pgm_read_byte(&test_vectors[i].nk);
    nr = pgm_read_byte(&test_vectors[i].nr);
    memset  (&key[0], TEST_MAGIC, sizeof(key));
    memcpy_P(&key[0], pgm_read_ptr(&test_vectors[i].key), min(sizeof(key), 4 * nk));
    
    printf_P(PSTR("Test vector %d/%d for nk=%d, nr=%d (%d bits)\n"), i + 1, n, nk, nr, (uint16_t)nk * 32);

    bool test_ok = true;

    // Check for oof-by-one etc
    memset(&xkey[0], TEST_MAGIC, sizeof(xkey));
    TestAES_ExpandKey(&key[0], &xkey[0], nk, nr);
    for (uint16_t j = (nr + 1) * AES_RKEYSIZE; j < sizeof(xkey); j++)
      test_ok &= (xkey[j] == TEST_MAGIC);


    if (!test_ok)
      printf_P(PSTR("Fatal error: TestAES_ExpandKey buffer overflow\n"));

    //Chceck if copied key is OK
    if (memcmp_P(&xkey[0], pgm_read_ptr(&test_vectors[i].key), nk * 4))
    {
      printf_P(PSTR("Fatal error: TestAES_ExpandKey bad initial key\n"));
      test_ok = false;
    }

    //Check if last expanded key is OK
    if (memcmp_P(&xkey[nr * AES_RKEYSIZE], pgm_read_ptr(&test_vectors[i].lastkey), AES_RKEYSIZE)) //arg2 = progmem
    {
      printf_P(PSTR("Fatal error: TestAES_ExpandKey bad key%d\n"), nr);
      test_ok = false;
    }
    if (!test_ok)
    {
      Serial.println("EXIT");
      return false;
    }

    for (uint8_t j = 0; j < 8; j++)
    {
      test_ok = true;
      uint8_t test_case = 0; //none
      const char *fname = PSTR("None");
      uint8_t wrapped_params=0;

      memset(&xtest[0], TEST_MAGIC, sizeof(xtest));
      memset(&testblock[0], TEST_MAGIC, sizeof(testblock));
#ifdef AES_BENCHMARK
      cli();
      TCNT1=0;
#endif
      switch (j)
      {
        // Universal function - Flash
        case 0:
          AES_ExpandKey_F(&key[0], &xtest[0], nk, nr);
          fname = PSTR("AES_ExpandKey_F");
          test_case = 1;
          break;

#ifdef TEST_RAM
        // Universal function - RAM
        case 1:
          AES_ExpandKey_R(&key[0], &xtest[0], nk, nr);
          fname = PSTR("AES_ExpandKey_R");
          test_case = 1;
          break;
#endif
        // Fixed key length functions - Flash
        case 2:
          if (nk == 4)
          {
            AES_ExpandKey128_F(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey128_F");
            test_case = 1;
          }
          else if (nk == 6)
          {
            AES_ExpandKey192_F(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey192_F");
            test_case = 1;
          }
          else if (nk == 8)
          {
            AES_ExpandKey256_F(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey256_F");
            wrapped_params = 2;
            test_case = 1;
          }
          break;

#ifdef TEST_RAM
        // Fixed key length functions - RAM
        case 3:
          if (nk == 4)
          {
            AES_ExpandKey128_R(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey128_R");
            test_case = 1;
          }
          else if (nk == 6)
          {
            AES_ExpandKey192_R(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey192_R");
            test_case = 1;
          }
          else if (nk == 8)
          {
            AES_ExpandKey256_R(&key[0], &xtest[0]);
            fname = PSTR("AES_ExpandKey256_R");
            wrapped_params = 2;
            test_case = 1;
          }
          break;
#endif

        // Tiny RAM - forward key expansion
        case 4:
          if (nk == 4)
          {
            AES_ExpandLastKey128_T(&key[0], &key[0]);
            fname = PSTR("AES_ExpandLastKey128_T");
            test_case=2;
          }
          break;

        // Tiny RAM - reverse key expansion
        case 5:
          if (nk == 4)
          {
            memcpy_P(&key[0],pgm_read_ptr(&test_vectors[i].lastkey),4*nk);
            AES_ExpandFirstKey128_T(&key[0], &key[0]);
            fname = PSTR("AES_ExpandFirstKey128_T");
            test_case=3;
          }
          break;

        // Tiny RAM - encryption (also forward key expansion)
        case 6:
          if (nk == 4)
          {
            AES_Encrypt128_T(&testblock[0], &testblock[0], &key[0]);
            fname = PSTR("AES_Encrypt128_T");
            test_case = 2;
          }
          break;
        // Tiny RAM - decryption (also reverse key expansion)
        case 7:
          if (nk == 4)
          {
            memcpy_P(&key[0],pgm_read_ptr(&test_vectors[i].lastkey),4*nk);
            AES_Decrypt128_T(&testblock[0], &testblock[0], &key[0]);
            fname = PSTR("AES_Decrypt128_T");
            test_case = 3;
          }
          break;
      }
#ifdef AES_BENCHMARK
      sei();
#endif
      
      strncpy_P(fname_buf, fname, sizeof(fname_buf));
      //Serial.print(fname_buf);
      //Serial.print(", case=");
      //Serial.println(test_case);
      //delay(100);
      switch (test_case)
      {
        //Full compare
        case 1:
          if (memcmp(&xkey[0], &xtest[0], sizeof(xtest)))
          {
            printf_P(PSTR("%-23s: FAILED\n"), fname_buf);
            test_ok = false;

            printf_P(PSTR("List of differences\n"));
            for (uint16_t x = 0; x < sizeof(xtest); x++)
              if (xkey[x] != xtest[x])
                printf_P(PSTR("%03x: %02x %02x\n"), x, xkey[x], xtest[x]);
          }
          else
          {
#ifdef AES_BENCHMARK
            printf_P(PSTR("%-23s: OK, "), fname_buf);
	          print_cycles(wrapped_params);
#else
            printf_P(PSTR("%-23s: OK\n"), fname_buf);
#endif
          }
          break;

        //Last only
        case 2:
        case 3:
          if (test_case == 2)
            ptr = (const uint8_t *)pgm_read_ptr(&test_vectors[i].lastkey);
          else
            ptr = (const uint8_t *)pgm_read_ptr(&test_vectors[i].key);
          
          if (memcmp_P(&key[0], ptr , 4 * nk))
            test_ok = false;
          for (uint8_t x = nk * 4; x < sizeof(key); x++)
            test_ok &= (key[x] == TEST_MAGIC);

          if (test_ok)
          {
#ifdef AES_BENCHMARK
            printf_P(PSTR("%-23s: OK, "), fname_buf);
	          print_cycles(wrapped_params);
#else
            printf_P(PSTR("%-23s: OK\n"), fname_buf);
#endif
          }
          else
          {
            printf_P(PSTR("%-23s: FAILED\n"), fname_buf);
            test_ok = false;

            printf_P(PSTR("List of differences\n"));
            for (uint8_t x = 0; x < nk * 4; x++)
            {
              uint8_t y = pgm_read_byte(ptr+x);
              if (key[x] != y)
                printf_P(PSTR("%03x: %02x %02x\n"), x, key[x], y);
            }
            for (uint8_t x = nk * 4; x < sizeof(key); x++)
              if (key[x] != TEST_MAGIC)
                printf_P(PSTR("%03x: %02x %02x\n"), x, key[x], TEST_MAGIC);
          }
      }
      ok &= test_ok;
    }
    printf("\n");
  }
  return ok;
}

bool test_encryption()
{
  uint8_t plaintext[AES_BLOCKSIZE],ciphertext[AES_BLOCKSIZE],outblock[AES_BLOCKSIZE];
  uint8_t xkey [AES256_XKEYSIZE];
  char    fname_buf[24];
  uint8_t nk, nr;
  uint8_t n = sizeof(test_vectors) / sizeof(test_vectors[0]);
  const uint8_t *ptr;

  printf_P(PSTR("< << <<< <<<< <<<<< <<<<<< ENCRYPTION/DECRYPTION >>>>>> >>>>> >>>> >>> >> >\n\n"));
  
  bool ok = true;
  for (uint8_t i = 0; i < n; i++)
  {
    nk = pgm_read_byte(&test_vectors[i].nk);
    nr = pgm_read_byte(&test_vectors[i].nr);

    
    memcpy_P(&plaintext [0], pgm_read_ptr(&test_vectors[i].plaintext ), sizeof(plaintext));
    memcpy_P(&ciphertext[0], pgm_read_ptr(&test_vectors[i].ciphertext), sizeof(ciphertext));
    
    printf_P(PSTR("Test vector %d/%d for nk=%d, nr=%d (%d bits)\n"), i + 1, n, nk, nr, (uint16_t)nk * 32);

    bool test_ok = true;

    for (uint8_t j=0;j<10;j++)
    {
      const char *fname = PSTR("None");
      test_ok = true;
      uint8_t test_case = 0;
      uint8_t wrapped_params=0;

      memcpy_P(&xkey[0], pgm_read_ptr(&test_vectors[i].key), min(sizeof(xkey), 4 * nk));  
      TestAES_ExpandKey(&xkey[0], &xkey[0], nk, nr); //Slow but good
      memset(&outblock[0],TEST_MAGIC,sizeof(outblock));
#ifdef AES_BENCHMARK
      cli();
#endif
      TCNT1=0;
      switch (j)
      {
        case 0:
          AES_Encrypt_F(&plaintext[0],&outblock[0],&xkey[0],nr);
          fname = PSTR("AES_Encrypt_F");
          test_case = 1;
          break;

#ifdef TEST_RAM          
        case 1:
          AES_Encrypt_R(&plaintext[0],&outblock[0],&xkey[0],nr);
          fname = PSTR("AES_Encrypt_R");
          test_case = 1;
          break;
#endif
          
        case 2:
          if (nk == 4)
          {
            AES_Encrypt128_F(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt128_F");
            wrapped_params = 1;
            test_case = 1;
          }
          else if (nk == 6)
          {
            AES_Encrypt192_F(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt192_F");
            wrapped_params = 1;
            test_case = 1;
          }
          else if (nk == 8)
          {
            AES_Encrypt256_F(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt256_F");
            wrapped_params = 1;
            test_case = 1;
          }
          break;

#ifdef TEST_RAM
        case 3:
          if (nk == 4)
          {
            AES_Encrypt128_R(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt128_R");
            wrapped_params = 1;
            test_case = 1;
          }
          else if (nk == 6)
          {
            AES_Encrypt192_R(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt192_R");
            wrapped_params = 1;
            test_case = 1;
          }
          else if (nk == 8)
          {
            AES_Encrypt256_R(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt256_R");
            wrapped_params = 1;
            test_case = 1;
          }
          break;
#endif

        case 4:
          if (nk == 4)
          {
            AES_Encrypt128_T(&plaintext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Encrypt_T");
            test_case = 1;
          }
          break;

        case 5:
          AES_Decrypt_F(&ciphertext[0],&outblock[0],&xkey[0],nr);
          fname = PSTR("AES_Decrypt_F");
          test_case = 2;
          break;

#ifdef TEST_RAM          
        case 6:
          AES_Decrypt_R(&ciphertext[0],&outblock[0],&xkey[0],nr);
          fname = PSTR("AES_Decrypt_R");
          test_case = 2;
          break;
#endif
          
        case 7:
          if (nk == 4)
          {
            AES_Decrypt128_F(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt128_F");
            test_case = 2;
          }
          else if (nk == 6)
          {
            AES_Decrypt192_F(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt192_F");
            test_case = 2;
          }
          else if (nk == 8)
          {
            AES_Decrypt256_F(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt256_F");
            test_case = 2;
          }
          break;

#ifdef TEST_RAM          
        case 8:
          if (nk == 4)
          {
            AES_Decrypt128_R(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt128_R");
            test_case = 2;
          }
          else if (nk == 6)
          {
            AES_Decrypt192_R(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt192_R");
            test_case = 2;
          }
          else if (nk == 8)
          {
            AES_Decrypt256_R(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt256_R");
            test_case = 2;
          }
          break;
#endif
          
        case 9:
          if (nk == 4)
          {
            AES_ExpandLastKey128_T(&xkey[0],&xkey[0]); //Example how to use 
            AES_Decrypt128_T(&ciphertext[0],&outblock[0],&xkey[0]);
            fname = PSTR("AES_Decrypt_T");
            test_case = 2;
          }
          break;
      }
#ifdef AES_BENCHMARK      
      sei();
#endif      
      strncpy_P(fname_buf, fname, sizeof(fname_buf));  
      
      if (test_case)
      {
        if (test_case == 1)
          ptr = pgm_read_ptr(&test_vectors[i].ciphertext);
        else
          ptr = pgm_read_ptr(&test_vectors[i].plaintext);
        
        if (memcmp_P(&outblock[0],ptr,AES_BLOCKSIZE))
        {
          printf_P(PSTR("%-23s: FAILED\n"), fname_buf);
          test_ok = false;

          printf_P(PSTR("List of differences\n"));
          for (uint16_t x=0; x< AES_BLOCKSIZE;x++)
          {
              uint8_t y = pgm_read_byte(ptr+x);
              if (outblock[x] != y)
                printf_P(PSTR("%03x: %02x %02x\n"), x, outblock[x], y);
          }
        }
        else
        {
#ifdef AES_BENCHMARK
          printf_P(PSTR("%-23s: OK, "), fname_buf);
          print_cycles(wrapped_params);
#else
          printf_P(PSTR("%-23s: OK\n"), fname_buf);
#endif
        }
      }
      ok &= test_ok;
    }
    printf("\n");
  }
  return ok;
}    
      

uint32_t rev(const uint8_t *x)
{
  return (((uint32_t)x[0]) <<  24) |
         (((uint32_t)x[1]) <<  16) |
         (((uint32_t)x[2]) <<   8) |
         (((uint32_t)x[3]) <<   0);

}



// Use more programmer-friendly I/O
// https://www.nongnu.org/avr-libc/user-manual/group__avr__stdio.html
// see: Running stdio without malloc()

static int uart_putchar (char c, FILE *stream __attribute__((unused)))
{
  Serial.write(c) ;
  return 0 ;
}
static FILE mystdout;

#ifdef TEST_RAM
uint8_t AES_SBox_R   [256];
uint8_t AES_InvSBox_R[256];
#endif

void setup() {
  Serial.begin(115200);
  //"Connect" Serial to STDOUT
  fdev_setup_stream (&mystdout, uart_putchar, NULL, _FDEV_SETUP_WRITE);
  stdout = &mystdout ;

  printf_P(PSTR("\n\n"
    "[ [[ [[[ [[[[ [[[[[ [[[[[[ [[[[[[[ START ]]]]]]] ]]]]]] ]]]]] ]]]] ]]] ]] ]\n\n"
    " AVR-AES-Faster test sketch (c) 2020 Radosław Gancarz\n\n"
#ifndef AES_BENCHMARK    
    " Hint: Set AES_BENCHMARK in AVR-AES-Faster-devel.h and rebuild to see\n"
    "       timing information for low level part (inccluding C/C++ ABI\n"
    "       overhead)\n\n"
#endif    
    ));

#ifdef TEST_RAM
  //Make *_R function work
  memcpy_P(AES_SBox_R   , AES_SBox_F   , sizeof(AES_SBox_R   ));
  memcpy_P(AES_InvSBox_R, AES_InvSBox_F, sizeof(AES_InvSBox_R));
#endif

#ifdef AES_BENCHMARK
  //Use timer1 for benchmarking
  TCCR1A = 0;
  TCCR1B = _BV(WGM12) | _BV(CS10) ; //CTC mode, CLK/1
  TIMSK1 = 0;
  OCR1A = 0xffff; //0xff;
#endif

  bool ok = true;
  ok &= test_expansion();
  ok &= test_encryption(); 
  
  if (ok)
    printf_P(PSTR("+ ++ +++ ++++ +++++ ++ ALL TEST PASSED SUCCESSFULLY! ++ +++++ ++++ +++ ++ +\n\n"));
  else
    printf_P(PSTR("-  FAILED !!!  FAILED !!!  FAILED !!!  FAILED !!!  FAILED !!!  FAILED !!! -\n\n"));
#ifdef AES_BENCHMARK
  print_sizes();
#endif
}

void loop() {}
