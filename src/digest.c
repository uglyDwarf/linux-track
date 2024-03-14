
#include "digest.h"
#include <stdbool.h>
#include <stdio.h>

//#define DEBUG

static uint8_t s[64] = {
	 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 7, 12, 17, 22,
	 5,  9, 14, 20,  5,  9, 14, 20,  5, 9, 14, 20,  5,  9, 14, 20,
	 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, 4, 11, 16, 23,
	 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t k[64] = {
	0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
	0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
	0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
	0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
	0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
	0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
	0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
	0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
	0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
	0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
	0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
	0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
	0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
	0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
	0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
	0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static uint32_t a0 = 0x67452301;
static uint32_t b0 = 0xEFCDAB89;
static uint32_t c0 = 0x98BADCFE;
static uint32_t d0 = 0x10325476;
static uint32_t h4 = 0xC3D2E1F0;

static uint32_t swap_endian32(uint32_t val)
{
  uint8_t *map = (uint8_t *)&val;
  uint8_t res[4];
  for(int i = 0; i < 4; ++i){
    res[i] = map[3-i];
  }
  return *(uint32_t*)res;
}

static uint64_t swap_endian64(uint64_t val)
{
  uint8_t *map = (uint8_t*)&val;
  uint8_t res[8];
  for(int i = 0; i < 8; ++i){
    res[i] = map[7-i];
  }
  return *(uint64_t*)res;
}

static uint32_t left_rotate(uint32_t val, uint8_t amount)
{
  uint8_t rot = amount & 31;
  return ((val >> (32 - rot)) | (val << rot));
}

static void md5_round(const uint32_t data[], uint32_t *p_a, uint32_t *p_b, uint32_t *p_c, uint32_t *p_d)
{
  uint32_t a = *p_a;
  uint32_t b = *p_b;
  uint32_t c = *p_c;
  uint32_t d = *p_d;
  uint32_t f, g;
  for(uint8_t j = 0; j < 64; ++j){
    if(j < 16){
      f = (b & c) | ((~b) & d);
      g = j;
    }else if(j < 32){
      f = (d & b) | ((~d) & c);
      g = (5*j + 1) & 0xF;
    }else if(j < 48){
      f = b ^ c ^ d;
      g = (3*j + 5) & 0xF;
    }else{
      f = c ^ (b | (~d));
      g = (7*j) & 0xF;
    }
#ifdef DEBUG
    printf("%d: F=%u, g = %d\n", j, f, g);
#endif
    f += a + k[j] + data[g];
#ifdef DEBUG
    printf("    F=%u, a = %u, k = %u, data = %u\n", f, a, k[j], data[g]);
#endif
    a = d;
    d = c;
    c = b;
    b = b + left_rotate(f, s[j]);

#ifdef DEBUG
    printf("  A: %u\n  B: %u\n  C: %u\n D: %u\n\n", a, b, c, d);
#endif
  }
  *p_a += a;
  *p_b += b;
  *p_c += c;
  *p_d += d;
}

void sha1_round(const uint32_t data[], uint32_t *p_h0, uint32_t *p_h1, uint32_t *p_h2, uint32_t *p_h3, uint32_t *p_h4)
{
  uint32_t a = *p_h0;
  uint32_t b = *p_h1;
  uint32_t c = *p_h2;
  uint32_t d = *p_h3;
  uint32_t e = *p_h4;
  uint32_t f, k;
  uint32_t w[80];
  for(uint8_t j = 0; j < 80; ++j){
    if(j < 20){
      f = (b & c) ^ ((~b) & d);
      k = 0x5A827999;
    }else if(j < 40){
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    }else if(j < 60){
      f = (b & c) ^ (b & d) ^ (c & d);
      k = 0x8F1BBCDC;
    }else{
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
#ifdef DEBUG
    printf("%d: F=%u, k = %d\n", j, f, k);
#endif
    if(j < 16){
      w[j] = swap_endian32(data[j]);
    }else{
      w[j] = left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
    }
    uint32_t tmp = left_rotate(a, 5) + f + e + k + w[j];
#ifdef DEBUG
    printf("    tmp=%u, (a rot 5) = %u, f = %u, e = %u, w = %u\n", tmp, left_rotate(a, 5), f, e, w[j]);
#endif
    e = d;
    d = c;
    c = left_rotate(b, 30);
    b = a;
    a = tmp;

#ifdef DEBUG
    printf("  A: %u\n  B: %u\n  C: %u\n D: %u E: %u\n\n", a, b, c, d, e);
#endif
  }
  *p_h0 += a;
  *p_h1 += b;
  *p_h2 += c;
  *p_h3 += d;
  *p_h4 += e;
}

uint8_t pad_message(const uint8_t data[], size_t len, uint8_t tail[], bool be)
{
  uint8_t tail_size = 1;
  // Padding
  uint64_t trunc_len = (len & 0xFFFFFFFFFFFFFFFFULL);
  uint8_t rest = (uint8_t)(trunc_len & 63);
  //trunc_len += 1;
  trunc_len <<= 3;
  if(rest > 55){
    tail_size = 2;
  }
#ifdef DEBUG
  printf("Orig length: %d, rest:%d, tail_size: %d\n", (int)len, rest, tail_size);
#endif
  uint8_t idx;
  const uint8_t *src = &data[len-rest-1];
  for(idx = 0; idx < rest; ++idx){
    tail[idx] = *(++src);
  }
  tail[idx] = 0x80;
  
  if(be) trunc_len = swap_endian64(trunc_len);

  if(tail_size == 1){
    *(uint64_t*)&(tail[56]) = trunc_len;
#ifdef DEBUG
    for(int q = 0; q < 64; ++q) printf("%02X ", tail[q]);
#endif
  }else{
    *(uint64_t*)&(tail[120]) = trunc_len;
#ifdef DEBUG
    for(int q = 0; q < 128; ++q) printf("%02X ", tail[q]);
#endif
  }
#ifdef DEBUG
  printf("\n");
#endif
  return tail_size;
}

void md5sum(const uint8_t data[], size_t len, uint32_t res[])
{

  uint8_t tail[128] = {0};
  uint8_t tail_size = 1;

  tail_size = pad_message(data, len, tail, false);

  res[0] = a0;
  res[1] = b0;
  res[2] = c0;
  res[3] = d0;
  uint32_t *ptr = (uint32_t*)data;
  size_t i;
  for(i = 0; i < (len >> 6); ++i){
    md5_round(ptr, &(res[0]), &(res[1]), &(res[2]), &(res[3]));
    ptr += 16;
  }
  ptr = (uint32_t*)tail;
  for(i = 0; i < tail_size; ++i){
    md5_round(ptr, &(res[0]), &(res[1]), &(res[2]), &(res[3]));
    ptr += 16;
  }
}

void sha1sum(const uint8_t data[], size_t len, uint32_t res[])
{

  uint8_t tail[128] = {0};
  uint8_t tail_size = 1;

  tail_size = pad_message(data, len, tail, true);

  res[0] = a0;
  res[1] = b0;
  res[2] = c0;
  res[3] = d0;
  res[4] = h4;
  uint32_t *ptr = (uint32_t*)data;
  size_t i;
  for(i = 0; i < (len >> 6); ++i){
    sha1_round(ptr, &(res[0]), &(res[1]), &(res[2]), &(res[3]), &(res[4]));
    ptr += 16;
  }
  ptr = (uint32_t*)tail;
  for(i = 0; i < tail_size; ++i){
    sha1_round(ptr, &(res[0]), &(res[1]), &(res[2]), &(res[3]), &(res[4]));
    ptr += 16;
  }
  for(int i = 0; i < 5; ++i){
    res[i] = swap_endian32(res[i]);
  }
}


