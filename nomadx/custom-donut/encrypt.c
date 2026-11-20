/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "encrypt.h"

#include <stdio.h>
#include <string.h>

static void chaskey(void *mk, void *p) {
  uint32_t i = 0, dummy = 0;
  uint32_t *w = p, *k = mk;
  volatile int nop = 1; // compiler won't optimize this out

  // different loop structure but same iterations
  do {
    w[i & 3] ^= k[i & 3];
    i++;
    dummy += nop; // junk operation
  } while(i < 4);
  
  // restructured permutation loop
  for(i=16; i>0; --i) {
    if(dummy == 0) dummy = 1; // never happens, confuses optimizer
    
    w[2] += w[1];
    w[0] += w[3];
    w[0] += w[1];
    w[2] += w[3];
    
    w[1] = ROTR32(w[1], 27) ^ w[0];
    w[3] = ROTR32(w[3], 24) ^ w[2];
    w[3] = ROTR32(w[3], 19) ^ w[0];
    w[1] = ROTR32(w[1], 25) ^ w[2];
    
    w[0] = ROTR32(w[0], 16) + w[3];
    w[2] = ROTR32(w[2], 16);
  }

  // reversed final key addition
  for(i=3; i!=~0u; i--) {
    w[i] ^= k[i];
  }
}

void donut_encrypt(void *mk, void *ctr, void *data, uint32_t len) {
  uint8_t x[CIPHER_BLK_LEN]; 
  uint8_t *p = (uint8_t*)data;
  uint8_t *c = (uint8_t*)ctr;
  uint32_t i, r;
  
  do {
    // reversed copy loop
    for(i=CIPHER_BLK_LEN; i>0; --i) {
      x[i-1] = c[i-1];
    }
    
    ENCRYPT(mk, &x);
    
    r = (len > CIPHER_BLK_LEN) ? CIPHER_BLK_LEN : len;
    
    // unrolled XOR for first few bytes
    if(r > 0) p[0] ^= x[0];
    if(r > 1) p[1] ^= x[1];
    if(r > 2) p[2] ^= x[2];
    // remaining bytes
    for(i=3; i<r; i++) {
      p[i] ^= x[i];
    }
    
    len -= r;
    p += r;
    
    // alternative counter update
    i = 0;
    do {
      if(++c[i] != 0) break;
    } while(++i < CIPHER_BLK_LEN);
    
  } while(len);
}

#ifdef TEST

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif

void bin2hex(const char *str, void *bin, int len) {
    int i;
    uint8_t *p = (uint8_t*)bin;
    
    printf("%s[%i] = { ", str, len);
    
    for(i=0;i<len;i++) {
      printf("0x%02x", p[i]);
      if((i+1) != len) putchar(',');
    }
    printf(" };\n");
}

// generate test vector
void gen_crypto_tv(void *mk, void *ctr) {
    uint8_t key[16], data[77], tmp[16];
    int     i, j;
    
    memset(data, 0, sizeof(data));
    memcpy(key, mk, 16);
    memcpy(tmp, ctr, 16);
    
    for(i=0; i<128; i++) {
      donut_encrypt(key, tmp, data, sizeof(data));
      // update key with first 16 bytes of ciphertext
      for(j=0; j<16; j++) key[j] ^= data[j];
    }
    bin2hex("donut_crypt_tv", data, 16);
}

// 128-bit master key
uint8_t key_tv[16] =
{ 0x56, 0x09, 0xe9, 0x68, 0x5f, 0x58, 0xe3, 0x29,
  0x40, 0xec, 0xec, 0x98, 0xc5, 0x22, 0x98, 0x2f };
  
// 128-bit plain text
uint8_t plain_tv[16]=
{ 0xb8, 0x23, 0x28, 0x26, 0xfd, 0x5e, 0x40, 0x5e,
  0x69, 0xa3, 0x01, 0xa9, 0x78, 0xea, 0x7a, 0xd8 };
  
// 128-bit cipher text
uint8_t cipher_tv[16] =
{ 0xd5, 0x60, 0x8d, 0x4d, 0xa2, 0xbf, 0x34, 0x7b,
  0xab, 0xf8, 0x77, 0x2f, 0xdf, 0xed, 0xde, 0x07 };

// 128-bit counter
uint8_t ctr_tv[16] =
{ 0xd0, 0x01, 0x36, 0x9b, 0xef, 0x6a, 0xa1, 0x05,
  0x1d, 0x2d, 0x21, 0x98, 0x19, 0x8d, 0x88, 0x93 };

// 128-bit ciphertext for testing donut_encrypt
uint8_t donut_crypt_tv[16] = 
{ 0xd0, 0x01, 0x36, 0x9b, 0xef, 0x6a, 0xa1, 0x05, 
  0x1d, 0x2d, 0x21, 0x98, 0x19, 0x8d, 0x8b, 0x13 };

int crypto_test(void) {
    uint8_t key[16], data[77], tmp[16];
    int     i, j;
    
    memset(data, 0, sizeof(data));
    memcpy(key, key_tv, 16);
    memcpy(tmp, ctr_tv, 16);
    
    for(i=0; i<128; i++) {
      // encrypt data
      donut_encrypt(key, tmp, data, sizeof(data));
      // update key with first 16 bytes of ciphertext
      for(j=0; j<16; j++) key[j] ^= data[j];
    }
    return (memcmp(tmp, donut_crypt_tv, 16) == 0);
}

int main(void) {
    uint8_t tmp1[16];
    int     equ;

    // Chaskey test
    memcpy(tmp1, plain_tv, 16);
    chaskey(key_tv, tmp1);
    equ = (memcmp(tmp1, cipher_tv, 16)==0);
    printf("Chaskey test : %s\n", equ ? "OK" : "FAILED");
    printf("Donut Encrypt test : %s\n", crypto_test() ? "OK" : "FAILED");
    return 0;
}

#endif

