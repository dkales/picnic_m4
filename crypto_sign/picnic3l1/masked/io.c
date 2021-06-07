/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */


#include "io.h"
#include "compat.h"

#include <string.h>
#if PICNIC_DEBUG_TRACE
#include <stdio.h>
#include <assert.h>
#endif



void mzd_to_char_array(uint8_t* dst, const mzd_local_t* data, size_t len) {
  const size_t word_count = (len + 7) / sizeof(uint64_t);
  const block_t* block    = CONST_BLOCK(data, 0);

  for (size_t i = word_count; i; --i, dst += sizeof(uint64_t), len -= sizeof(uint64_t)) {
    const uint64_t tmp = htobe64(block->w64[i - 1]);
    memcpy(dst, &tmp, MIN(sizeof(tmp), len));
  }
}

void masked_mzd_to_char_array(masked_uint8_t* dst, const masked_mzd_t* data, size_t len) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_to_char_array(dst->shares[j], &(data->shares[j]), len);
  }
}

void masked_mzd_to_unmasked_char_array(uint8_t* dst, const masked_mzd_t* data, size_t numbytes) {
  mzd_local_t tmp[1];
  mzd_reconstruct(tmp, data);
  mzd_to_char_array(dst, tmp, numbytes);
}

void mzd_from_char_array(mzd_local_t* result, const uint8_t* data, size_t len) {
  const size_t word_count = (len + 7) / sizeof(uint64_t);
  block_t* block          = BLOCK(result, 0);

  for (size_t i = word_count; i; --i, data += sizeof(uint64_t), len -= sizeof(uint64_t)) {
    uint64_t tmp = 0;
    memcpy(&tmp, data, MIN(sizeof(tmp), len));
    block->w64[i - 1] = be64toh(tmp);
  }
}

void masked_mzd_from_char_array(masked_mzd_t* result, const masked_uint8_t* data, size_t len) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_from_char_array(&(result->shares[j]), (uint8_t*)&(data->shares[j]), len);
  }
}

void masked_mzd_from_masked_tape(masked_mzd_t* result, const masked_tape_t* data, size_t len) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_from_char_array(&(result->shares[j]), (uint8_t*)&(data->shares[j]), len);
  }
}

#if PICNIC_DEBUG_TRACE
static void printHex(const char* s, const uint8_t* data, size_t len)
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }    
    printf("\n");
}
#endif

void mzd_print(char* label, const mzd_local_t* a, size_t len)
{
  #if PICNIC_DEBUG_TRACE
    uint8_t a_bytes[sizeof(mzd_local_t)];
    assert(len <= sizeof(mzd_local_t));
    mzd_to_char_array(a_bytes, a, len);
    printHex(label, a_bytes, len);
  #else
    UNUSED_PARAMETER(label);
    UNUSED_PARAMETER(a);
    UNUSED_PARAMETER(len);
  #endif
}

void masked_mzd_print(char* label, const masked_mzd_t* a, size_t len)
{
  #if PICNIC_DEBUG_TRACE
    mzd_local_t a_unshared[1];
    mzd_reconstruct(a_unshared, a);
    mzd_print(label, a_unshared, len);
  #else
    UNUSED_PARAMETER(label);
    UNUSED_PARAMETER(a);
    UNUSED_PARAMETER(len);
  #endif
}

#if defined(PICNIC_STATIC) || !defined(NDEBUG)
void print_hex(FILE* out, const uint8_t* data, size_t len) {
  for (size_t i = len; i; --i, ++data) {
    fprintf(out, "%02X", *data);
  }
}
#endif
