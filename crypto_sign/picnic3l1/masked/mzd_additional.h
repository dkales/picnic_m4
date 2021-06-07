/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

/* Inspired by m4ri's mzd implementation, but completely re-written for our use-case. */

#ifndef MZD_ADDITIONAL_H
#define MZD_ADDITIONAL_H

#include "macros.h"
#include "masking.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t word;
#define WORD_C(v) UINT64_C(v)

typedef union {
  word w64[4];
} block_t ATTR_ALIGNED(32);

/**
 * Representation of matrices and vectors
 *
 * The basic memory unit is a block of 256 bit. Each row is stored in (possible multiple) blocks
 * depending on the number of columns. Matrices with up to 128 columns are the only excpetion. In
 * this case a block actually contains two rows. The row with even index is contained in w64[0] and
 * w61[1], the row with odd index is contained in w64[2] and w64[3].
 */
typedef block_t mzd_local_t;

typedef struct masked_mzd_t {
  mzd_local_t shares[MASKING_T];
} masked_mzd_t;

void mzd_share(masked_mzd_t* shared, const mzd_local_t* unshared);
void mzd_reconstruct(mzd_local_t* unshared, const masked_mzd_t* shared);
void masked_mzd_refresh(masked_mzd_t* a);

void mzd_copy_uint64_192(mzd_local_t* dst, mzd_local_t const* src) ATTR_NONNULL;
void masked_mzd_copy_uint64_192(masked_mzd_t* dst, masked_mzd_t const* src) ATTR_NONNULL;
void mzd_random(mzd_local_t* dst, size_t bytelen) ATTR_NONNULL;

/**
 * mzd_xor variants
 */
void mzd_xor_uint64_192(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void mzd_xor_uint64_640(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void mzd_xor_uint64_960(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void mzd_xor_uint64_1216(mzd_local_t* res, mzd_local_t const* first,
                         mzd_local_t const* second) ATTR_NONNULL;
void masked_mzd_xor_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, masked_mzd_t const* second) ATTR_NONNULL;
void masked_mzd_xorconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, mzd_local_t const* second) ATTR_NONNULL;

/**
 * mzd_and variants
 */
void mzd_and_uint64_128(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void mzd_and_uint64_192(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void masked_mzd_andconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;                        
void mzd_and_uint64_256(mzd_local_t* res, mzd_local_t const* first,
                        mzd_local_t const* second) ATTR_NONNULL;
void masked_mzd_and_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, masked_mzd_t const* second) ATTR_NONNULL;

/**
 * shifts and rotations
 */
void mzd_shift_left_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count);
void mzd_shift_right_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count);
void masked_mzd_shift_left_uint64_192(masked_mzd_t* res, const masked_mzd_t* val, unsigned int count);
void masked_mzd_shift_right_uint64_192(masked_mzd_t* res, const masked_mzd_t* val, unsigned int count);
#if defined(PICNIC_STATIC)
/* only needed for tests */
void mzd_rotate_left_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count);
void mzd_rotate_right_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count);
#endif

/**
 * Compute v * A optimized for v being a vector.
 */
void mzd_mul_v_uint64_129(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* At) ATTR_NONNULL;
void mzd_mul_v_uint64_192(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* At) ATTR_NONNULL;
void mzd_mul_v_uint64_192_960(mzd_local_t* c, mzd_local_t const* v,
                              mzd_local_t const* At) ATTR_NONNULL;
void masked_mzd_mul_v_uint64_129(masked_mzd_t* c, masked_mzd_t const* v, mzd_local_t const* At) ATTR_NONNULL;                              

/**
 * Compute v * A optimized for v being a vector, for specific sizes depending on instance
 * Only work for specific sizes and RLL_NEXT algorithm using uint64 operations
 */
void mzd_addmul_v_uint64_30_192(mzd_local_t* c, mzd_local_t const* v,
                                mzd_local_t const* A) ATTR_NONNULL;

/**
 * Compute using parity based algorithm
 * */
void mzd_mul_v_parity_uint64_192_30(mzd_local_t* c, mzd_local_t const* v,
                                    mzd_local_t const* A) ATTR_NONNULL;

/**
 * Compute c + v * A optimized for c and v being vectors.
 */

void mzd_addmul_v_uint64_129(mzd_local_t* c, mzd_local_t const* v,
                             mzd_local_t const* A) ATTR_NONNULL;
void masked_mzd_addmul_v_uint64_129(masked_mzd_t* c, masked_mzd_t const* v, mzd_local_t const* A) ATTR_NONNULL;                             
void mzd_addmul_v_uint64_192(mzd_local_t* c, mzd_local_t const* v,
                             mzd_local_t const* A) ATTR_NONNULL;

/**
 * Shuffle vector x according to info in mask. Needed for OLLE optimiztaions.
 */
void mzd_shuffle_192_30(mzd_local_t* x, const word mask) ATTR_NONNULL;

#define BLOCK(v, b) ((block_t*)ASSUME_ALIGNED(&(v)[(b)], 32))
#define CONST_BLOCK(v, b) ((const block_t*)ASSUME_ALIGNED(&(v)[(b)], 32))

#endif
