#ifndef DIGEST__H
#define DIGEST__H

#include <stdio.h>
#include <stdint.h>

  #ifdef __cplusplus
    extern "C" {
  #endif

  #define MD5_DIGEST_LENGTH 16UL
  #define SHA_DIGEST_LENGTH 20UL
  void md5sum(const uint8_t data[], size_t len, uint32_t res[]);
  void sha1sum(const uint8_t data[], size_t len, uint32_t res[]);

  #ifdef __cplusplus
    }
  #endif

#endif
