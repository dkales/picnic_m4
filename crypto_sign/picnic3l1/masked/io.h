/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef IO_H
#define IO_H

#include <stdint.h>
#include <stdio.h>

#include "mzd_additional.h"

void mzd_to_char_array(uint8_t* dst, const mzd_local_t* data, size_t numbytes);
void mzd_from_char_array(mzd_local_t* result, const uint8_t* data, size_t len);

/* Print an mzd_local_t to the console. Only produces output when PICNIC_DEBUG_TRACE is set in masking.h */
void mzd_print(char* label, const mzd_local_t* a, size_t len);

/* Print the reconstructed version of a masked_mzd_local_t to the console. 
 * Only produces output when PICNIC_DEBUG_TRACE is set in masking.h 
 */
void masked_mzd_print(char* label, const masked_mzd_t* a, size_t len);

void masked_mzd_to_char_array(masked_uint8_t* dst, const masked_mzd_t* data, size_t numbytes);
void masked_mzd_to_unmasked_char_array(uint8_t* dst, const masked_mzd_t* data, size_t numbytes);
void masked_mzd_from_char_array(masked_mzd_t* result, const masked_uint8_t* data, size_t len);
void masked_mzd_from_masked_tape(masked_mzd_t* result, const masked_tape_t* data, size_t len);

/* Get one bit from a byte array */
static inline uint8_t getBit(const uint8_t* array, size_t bitNumber) {
  return (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

/* Set a specific bit in a byte array to a given value */
static inline void setBit(uint8_t* bytes, size_t bitNumber, uint8_t val) {
  bytes[bitNumber / 8] =
      (bytes[bitNumber >> 3] & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

static inline int check_padding_bits(const uint8_t byte, const unsigned int diff) {
  return byte & ~(UINT8_C(0xff) << diff);
}

#if defined(PICNIC_STATIC) || !defined(NDEBUG)
void print_hex(FILE* out, const uint8_t* data, size_t len);
#endif

#endif
