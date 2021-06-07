/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "compat.h"
#include "mzd_additional.h"
#include "randomness.h"

#if !defined(_MSC_VER)
#include <stdalign.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_MSC_VER) && !defined(static_assert)
#define static_assert _Static_assert
#endif

static_assert(((sizeof(mzd_local_t) + 0x1f) & ~0x1f) == 32, "sizeof mzd_local_t not supported");

#if 0  /* Used for debugging */
void mzd_share(masked_mzd_t* shared, const mzd_local_t* unshared){
#if 0
  // Non-randomized version:
  memset(shared, 0x00, sizeof(masked_mzd_t));
  mzd_copy_uint64_192(&shared->shares[0], unshared);
#else
  // randomized version:
  rand_mask((uint8_t*)&shared->shares[0], sizeof(mzd_local_t));
  mzd_xor_uint64_192(&shared->shares[1], &shared->shares[0], unshared);
#endif
 
}
#endif

/* Re-randomize the shares of a masked value.
 * See Gadget 4 (b) on page 12 of https://eprint.iacr.org/2015/506.pdf
*/
void masked_mzd_refresh(masked_mzd_t* a) {
  mzd_local_t r[1];
  assert(MASKING_T==2);

  mzd_random(r, 24);
  mzd_xor_uint64_192(&a->shares[0], &a->shares[0], r);
  mzd_xor_uint64_192(&a->shares[1], &a->shares[1], r);
}

void mzd_reconstruct(mzd_local_t* unshared, const masked_mzd_t* shared){
  mzd_xor_uint64_192(unshared, &(shared->shares[0]), &(shared->shares[1]));
  for(size_t j = 2; j < MASKING_T; j++){
    mzd_xor_uint64_192(unshared, unshared, &(shared->shares[j]));  // unshared += share[j]
  }
}

/* implementation of copy */

void mzd_copy_uint64_192(mzd_local_t* dst, mzd_local_t const* src) {
  const block_t* sblock = CONST_BLOCK(src, 0);
  block_t* dblock       = BLOCK(dst, 0);

  for (unsigned int i = 0; i < 3; ++i) {
    dblock->w64[i] = sblock->w64[i];
  }
}

void masked_mzd_copy_uint64_192(masked_mzd_t* dst, masked_mzd_t const* src) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_copy_uint64_192(&(dst->shares[j]), &(src->shares[j]));
  }
}

void mzd_random(mzd_local_t* dst, size_t bytelen) {
  rand_mask((uint8_t*) dst->w64, bytelen);
}

/* implementation of mzd_xor and variants */

static void mzd_xor_uint64_block(block_t* rblock, const block_t* fblock, const block_t* sblock,
                                 const unsigned int len) {
  for (unsigned int i = 0; i < len; ++i) {
    rblock->w64[i] = fblock->w64[i] ^ sblock->w64[i];
  }
}

void mzd_xor_uint64_192(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
  mzd_xor_uint64_block(BLOCK(res, 0), CONST_BLOCK(first, 0), CONST_BLOCK(second, 0), 3);
}

void masked_mzd_xor_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, masked_mzd_t const* second) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_xor_uint64_192(&(res->shares[j]), &(first->shares[j]), &(second->shares[j]));
  }
}

void masked_mzd_xorconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, mzd_local_t const* second) {
    mzd_xor_uint64_192(&(res->shares[0]), &(first->shares[0]), second);
    if(first!=res) {
      mzd_copy_uint64_192(&res->shares[1], &first->shares[1]);
    }
}


/* implementation of mzd_and_* and variants */

static inline void mzd_and_uint64_block(block_t* rblock, const block_t* fblock,
                                        const block_t* sblock, const unsigned int len) {
  for (unsigned int i = 0; i < len; ++i) {
    rblock->w64[i] = fblock->w64[i] & sblock->w64[i];
  }
}

void mzd_and_uint64_192(mzd_local_t* res, mzd_local_t const* first, mzd_local_t const* second) {
  mzd_and_uint64_block(BLOCK(res, 0), CONST_BLOCK(first, 0), CONST_BLOCK(second, 0), 3);
}

#if 0  // Alternatve versions of mzd_andconstant
static void DEBUG_masked_mzd_andconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, mzd_local_t const* second) {
  mzd_local_t res_unshared[1], first_unshared[1];
  memset(res, 0x00, sizeof(masked_mzd_t));
  mzd_reconstruct(first_unshared, first);
  mzd_and_uint64_192(res_unshared, first_unshared, second);
  mzd_share(res, res_unshared);
}
void masked_mzd_andconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, mzd_local_t const* second) {  
  // Version that creates masked value from second and uses masked AND.  
  memset(res, 0x00, sizeof(masked_mzd_t));
  masked_mzd_t masked_second[1] = {0};
  mzd_copy_uint64_192(&masked_second->shares[0], second);
  masked_mzd_and_uint64_192(res, first, masked_second);
}
#endif

void masked_mzd_andconstant_uint64_192(masked_mzd_t* res, masked_mzd_t const* first, mzd_local_t const* second) {
  /* E.g., when MASKING_T = 2, first = first0 + first1, and second is a constant, compute 
   * res = second *(first0 + first1) = second*first0 + second*first1    */
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_and_uint64_192(&res->shares[j], &first->shares[j], second);
  }
}


// Choose a version of masked_mzd_and
#if !MAKSING_RANDOMIZED_AND

// This version fixes t=2 and doesn't use additional randomization.  *Not* SNI-secure; heuristic countermeasure
void masked_mzd_and_uint64_192(masked_mzd_t* c, masked_mzd_t const* a, masked_mzd_t const* b) {
  // our two inputs are a = a0 + a1 and b = b0 + b1, we compute
  // c = a*b
  //   = (a0*b0 + a0*b1) + (a1*b0 + a1*b1) = c0 + c1
  mzd_local_t tmp[1];
  mzd_and_uint64_192(tmp, &a->shares[0], &b->shares[0]);
  mzd_and_uint64_192(&c->shares[0], &a->shares[0], &b->shares[1]);
  mzd_xor_uint64_192(&c->shares[0], &c->shares[0], tmp);

  mzd_and_uint64_192(tmp, &a->shares[1], &b->shares[0]);
  mzd_and_uint64_192(&c->shares[1], &a->shares[1], &b->shares[1]);
  mzd_xor_uint64_192(&c->shares[1], &c->shares[1], tmp);
}
#else   // This is SNI-mult from the paper, with t=2
void masked_mzd_and_uint64_192(masked_mzd_t* c, masked_mzd_t const* a, masked_mzd_t const* b) {
  mzd_local_t r0[1] ={0};
  mzd_local_t r1[1];
  mzd_local_t z0[1];  // Output is (z0, z1)
  mzd_local_t z1[1];

  mzd_and_uint64_192(z0, &a->shares[0], &b->shares[0]);
  mzd_and_uint64_192(z1, &a->shares[1], &b->shares[1]);

  mzd_random(r0, MAX(PICNIC_INPUT_SIZE, PICNIC_OUTPUT_SIZE));
  mzd_xor_uint64_192(z0, z0, r0);

  mzd_and_uint64_192(r1, &a->shares[0], &b->shares[1]);
  mzd_xor_uint64_192(r1, r1, r0);
  mzd_and_uint64_192(r0, &a->shares[1], &b->shares[0]); // use r0 as tmp to hold a1*b0, we don't need it anymore
  mzd_xor_uint64_192(r1, r1, r0);
  mzd_xor_uint64_192(&c->shares[1], z1, r1);
  mzd_copy_uint64_192(&c->shares[0], z0);

}
#endif

#if 0 // DEBUG version fo mzd_and that reconstructs 
void masked_mzd_and_uint64_192(masked_mzd_t* c, masked_mzd_t const* a, masked_mzd_t const* b) {
  mzd_local_t a_unshared[1], b_unshared[1], c_unshared[1];
  mzd_reconstruct(a_unshared, a);
  mzd_reconstruct(b_unshared, b);
  (void) mzd_compare(a_unshared, b_unshared); // NO-op, disables compiler warning about unused function
  mzd_and_uint64_192(c_unshared, a_unshared, b_unshared);
  memset(c, 0x00, sizeof(masked_mzd_t));
  mzd_copy_uint64_192(&(c->shares[0]), c_unshared);
}
#endif

/* shifts and rotations */

void mzd_shift_left_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count) {
  const unsigned int right_count = 8 * sizeof(word) - count;
  const block_t* block           = CONST_BLOCK(val, 0);
  block_t* rblock                = BLOCK(res, 0);

  rblock->w64[2] = (block->w64[2] << count) | (block->w64[1] >> right_count);
  rblock->w64[1] = (block->w64[1] << count) | (block->w64[0] >> right_count);
  rblock->w64[0] = block->w64[0] << count;
}
void masked_mzd_shift_left_uint64_192(masked_mzd_t* res, const masked_mzd_t* val, unsigned int count) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_shift_left_uint64_192(&(res->shares[j]), &(val->shares[j]), count);
  }
}

void mzd_shift_right_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count) {
  const unsigned int left_count = 8 * sizeof(word) - count;
  const block_t* block          = CONST_BLOCK(val, 0);
  block_t* rblock               = BLOCK(res, 0);

  rblock->w64[0] = (block->w64[0] >> count) | (block->w64[1] << left_count);
  rblock->w64[1] = (block->w64[1] >> count) | (block->w64[2] << left_count);
  rblock->w64[2] = block->w64[2] >> count;
}

void masked_mzd_shift_right_uint64_192(masked_mzd_t* res, const masked_mzd_t* val, unsigned int count) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_shift_right_uint64_192(&(res->shares[j]), &(val->shares[j]), count);
  }
}


#if defined(PICNIC_STATIC)

void mzd_rotate_left_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count) {
  const unsigned int right_count = 8 * sizeof(word) - count;
  const block_t* block           = CONST_BLOCK(val, 0);
  block_t* rblock                = BLOCK(res, 0);

  const word tmp = block->w64[2] >> right_count;
  rblock->w64[2] = (block->w64[2] << count) | (block->w64[1] >> right_count);
  rblock->w64[1] = (block->w64[1] << count) | (block->w64[0] >> right_count);
  rblock->w64[0] = (block->w64[0] << count) | tmp;
}

void mzd_rotate_right_uint64_192(mzd_local_t* res, const mzd_local_t* val, unsigned int count) {
  const unsigned int left_count = 8 * sizeof(word) - count;
  const block_t* block          = CONST_BLOCK(val, 0);
  block_t* rblock               = BLOCK(res, 0);

  const word tmp = block->w64[0] << left_count;
  rblock->w64[0] = (block->w64[0] >> count) | (block->w64[1] << left_count);
  rblock->w64[1] = (block->w64[1] >> count) | (block->w64[2] << left_count);
  rblock->w64[2] = (block->w64[2] >> count) | tmp;
}

#endif

static void clear_uint64_block(block_t* block, const unsigned int idx) {
  for (unsigned int i = 0; i < idx; ++i) {
    block->w64[i] = 0;
  }
}

static void mzd_xor_mask_uint64_block(block_t* rblock, const block_t* fblock, const word mask,
                                      const unsigned int idx) {
  for (unsigned int i = 0; i < idx; ++i) {
    rblock->w64[i] ^= fblock->w64[i] & mask;
  }
}

void mzd_addmul_v_uint64_129(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  block_t* cblock       = BLOCK(c, 0);
  const word* vptr      = CONST_BLOCK(v, 0)->w64;
  const block_t* Ablock = CONST_BLOCK(A, 0);

  {
    word idx            = (*vptr) >> 63;
    const uint64_t mask = -(idx & 1);
    mzd_xor_mask_uint64_block(cblock, Ablock, mask, 3);
    Ablock++;
    vptr++;
  }

  for (unsigned int w = 2; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int i = sizeof(word) * 8; i; --i, idx >>= 1, ++Ablock) {
      const uint64_t mask = -(idx & 1);
      mzd_xor_mask_uint64_block(cblock, Ablock, mask, 3);
    }
  }
}

void mzd_mul_v_uint64_129(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  clear_uint64_block(BLOCK(c, 0), 3);
  mzd_addmul_v_uint64_129(c, v, A);
}

void mzd_addmul_v_uint64_192(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  block_t* cblock       = BLOCK(c, 0);
  const word* vptr      = CONST_BLOCK(v, 0)->w64;
  const block_t* Ablock = CONST_BLOCK(A, 0);

  for (unsigned int w = 3; w; --w, ++vptr) {
    word idx = *vptr;
    for (unsigned int i = sizeof(word) * 8; i; --i, idx >>= 1, ++Ablock) {
      const uint64_t mask = -(idx & 1);
      mzd_xor_mask_uint64_block(cblock, Ablock, mask, 3);
    }
  }
}

void mzd_mul_v_uint64_192(mzd_local_t* c, mzd_local_t const* v, mzd_local_t const* A) {
  clear_uint64_block(BLOCK(c, 0), 3);
  mzd_addmul_v_uint64_192(c, v, A);
}


void masked_mzd_addmul_v_uint64_129(masked_mzd_t* c, masked_mzd_t const* v, mzd_local_t const* A) {
  for(size_t j = 0; j < MASKING_T; j++) {
    mzd_addmul_v_uint64_129(&(c->shares[j]), &(v->shares[j]), A);
  }
}
void masked_mzd_mul_v_uint64_129(masked_mzd_t* c, masked_mzd_t const* v, mzd_local_t const* A) {
    for(size_t j = 0; j < MASKING_T; j++) {
        clear_uint64_block(BLOCK(&(c->shares[j]), 0), 3);
        mzd_addmul_v_uint64_129(&(c->shares[j]), &(v->shares[j]), A);
    }

}

// no SIMD
