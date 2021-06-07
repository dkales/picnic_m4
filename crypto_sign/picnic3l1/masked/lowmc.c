/*
 *  This file is part of the optimized implementation of the Picnic signature
 * scheme. See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "lowmc.h"
#include "bitstream.h"
#include "io.h"
#include "mzd_additional.h"
#include "picnic3_impl.h"
#include "picnic3_types.h"

#if !defined(_MSC_VER)
#include <stdalign.h>
#endif
#include <assert.h>
#include <string.h>

#include "lowmc_129_129_4.h"

/**
 * S-box for m = 43
 */
static void sbox_uint64_lowmc_129_129_4(mzd_local_t* in) {
  mzd_local_t x0m[1], x1m[1], x2m[1];
  // a
  mzd_and_uint64_192(x0m, mask_129_129_43_a, in);
  // b
  mzd_and_uint64_192(x1m, mask_129_129_43_b, in);
  // c
  mzd_and_uint64_192(x2m, mask_129_129_43_c, in);

  mzd_shift_left_uint64_192(x0m, x0m, 2);
  mzd_shift_left_uint64_192(x1m, x1m, 1);

  mzd_local_t t0[1], t1[1], t2[1];
  // b & c
  mzd_and_uint64_192(t0, x1m, x2m);
  // c & a
  mzd_and_uint64_192(t1, x0m, x2m);
  // a & b
  mzd_and_uint64_192(t2, x0m, x1m);

  // (b & c) ^ a
  mzd_xor_uint64_192(t0, t0, x0m);

  // (c & a) ^ a ^ b
  mzd_xor_uint64_192(t1, t1, x0m);
  mzd_xor_uint64_192(t1, t1, x1m);

  // (a & b) ^ a ^ b ^c
  mzd_xor_uint64_192(t2, t2, x0m);
  mzd_xor_uint64_192(t2, t2, x1m);
  mzd_xor_uint64_192(t2, t2, x2m);

  mzd_shift_right_uint64_192(t0, t0, 2);
  mzd_shift_right_uint64_192(t1, t1, 1);

  mzd_xor_uint64_192(t2, t2, t1);
  mzd_xor_uint64_192(in, t2, t0);
}

//#define LOWMC_N LOWMC_129_129_4_N
#define XOR mzd_xor_uint64_192
#define AND mzd_and_uint64_192
#define SHL mzd_shift_left_uint64_192
#define SHR mzd_shift_right_uint64_192
#define bitmask_a mask_129_129_43_a
#define bitmask_b mask_129_129_43_b
#define bitmask_c mask_129_129_43_c

static void sbox_aux_uint64_lowmc_129_129_4(mzd_local_t* statein, mzd_local_t* stateout, randomTape_t* tapes)
{
    mzd_local_t a[1], b[1], c[1];

    AND(a, bitmask_a, statein);
    AND(b, bitmask_b, statein);
    AND(c, bitmask_c, statein);

    SHL(a, a, 2);
    SHL(b, b, 1);
    mzd_local_t d[1], e[1], f[1];

    AND(d, bitmask_a, stateout);
    AND(e, bitmask_b, stateout);
    AND(f, bitmask_c, stateout);

    SHL(d, d, 2);
    SHL(e, e, 1);

    mzd_local_t fresh_output_ab[1], fresh_output_bc[1], fresh_output_ca[1];
    XOR(fresh_output_ab, a, b);
    XOR(fresh_output_ca, e, fresh_output_ab);
    XOR(fresh_output_bc, d, a);
    XOR(fresh_output_ab, fresh_output_ab, c);
    XOR(fresh_output_ab, fresh_output_ab, f);

    mzd_local_t t0[1], t1[1], t2[1], aux[1];
    SHR(t2, fresh_output_ca, 2);
    SHR(t1, fresh_output_bc, 1);
    XOR(t2, t2, t1);
    XOR(aux, t2, fresh_output_ab);

    AND(t0, a, b);
    AND(t1, b, c);
    AND(t2, c, a);

    SHR(t2, t2, 2);
    SHR(t1, t1, 1);
    XOR(t2, t2, t1);
    XOR(t2, t2, t0);
    XOR(aux, aux, t2);

    bitstream_t parity_tape     = {{tapes->parity_tapes}, tapes->pos};
    bitstream_t last_party_tape = {{tapes->tape[15]}, tapes->pos};

    /* calculate aux_bits to fix and_helper */
    mzd_from_bitstream(&parity_tape, t0, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    XOR(aux, aux, t0);
    mzd_from_bitstream(&last_party_tape, t1, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    XOR(aux, aux, t1);

    last_party_tape.position = tapes->pos;
    mzd_to_bitstream(&last_party_tape, aux, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    bitstream_t aux_tape = {{tapes->aux_bits}, tapes->aux_pos};
    mzd_to_bitstream(&aux_tape, aux, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);

    tapes->aux_pos += LOWMC_N;
}

static void masked_sbox_aux_uint64_lowmc_129_129_4(masked_mzd_t* statein, masked_mzd_t* stateout, maskedRandomTape_t* tapes)
{
    masked_mzd_t a[1], b[1], c[1];
    masked_mzd_andconstant_uint64_192(a, statein, bitmask_a);
    masked_mzd_andconstant_uint64_192(b, statein, bitmask_b);
    masked_mzd_andconstant_uint64_192(c, statein, bitmask_c);

    masked_mzd_shift_left_uint64_192(a, a, 2);
    masked_mzd_shift_left_uint64_192(b, b, 1);

    masked_mzd_t d[1], e[1], f[1];
    masked_mzd_andconstant_uint64_192(d, stateout, bitmask_a);
    masked_mzd_andconstant_uint64_192(e, stateout, bitmask_b);
    masked_mzd_andconstant_uint64_192(f, stateout, bitmask_c);

    masked_mzd_shift_left_uint64_192(d, d, 2);
    masked_mzd_shift_left_uint64_192(e, e, 1);

    masked_mzd_t fresh_output_ab[1], fresh_output_bc[1], fresh_output_ca[1];
    masked_mzd_xor_uint64_192(fresh_output_ab, a, b);
    masked_mzd_xor_uint64_192(fresh_output_ca, e, fresh_output_ab);
    masked_mzd_xor_uint64_192(fresh_output_bc, d, a);
    masked_mzd_xor_uint64_192(fresh_output_ab, fresh_output_ab, c);
    masked_mzd_xor_uint64_192(fresh_output_ab, fresh_output_ab, f);

    masked_mzd_t t0[1], t1[1], t2[1], aux[1];
    masked_mzd_shift_right_uint64_192(t2, fresh_output_ca, 2);
    masked_mzd_shift_right_uint64_192(t1, fresh_output_bc, 1);
    masked_mzd_xor_uint64_192(t2, t2, t1);
    masked_mzd_xor_uint64_192(aux, t2, fresh_output_ab);

    masked_mzd_and_uint64_192(t0, a, b);
    masked_mzd_and_uint64_192(t1, b, c);
    masked_mzd_and_uint64_192(t2, c, a);

    masked_mzd_shift_right_uint64_192(t2, t2, 2);
    masked_mzd_shift_right_uint64_192(t1, t1, 1);
    masked_mzd_xor_uint64_192(t2, t2, t1);
    masked_mzd_xor_uint64_192(t2, t2, t0);
    masked_mzd_xor_uint64_192(aux, aux, t2);


    masked_bitstream_t parity_tape = {{
      {{tapes->parity_tapes.shares[0]}, tapes->pos},
      {{tapes->parity_tapes.shares[1]}, tapes->pos},
    }};
    masked_bitstream_t last_party_tape = {{
      {{tapes->tape[15].shares[0]}, tapes->pos},
      {{tapes->tape[15].shares[1]}, tapes->pos},
    }};

    /* calculate aux_bits to fix and_helper */
    masked_mzd_from_masked_bitstream(&parity_tape, t0, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    masked_mzd_xor_uint64_192(aux, aux, t0);
    masked_mzd_from_masked_bitstream(&last_party_tape, t1, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    masked_mzd_xor_uint64_192(aux, aux, t1);

    last_party_tape.shares[0].position = tapes->pos;
    last_party_tape.shares[1].position = tapes->pos;
    masked_mzd_to_masked_bitstream(&last_party_tape, aux, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    masked_bitstream_t aux_tape = {{
      {{tapes->aux_bits.shares[0]}, tapes->aux_pos},
      {{tapes->aux_bits.shares[1]}, tapes->aux_pos}
    }};
    masked_mzd_to_masked_bitstream(&aux_tape, aux, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);

    tapes->aux_pos += LOWMC_N;
}

// uint64 based implementation
#define IMPL uint64
#include "lowmc_fns_undef.h"
#define ADDMUL mzd_addmul_v_uint64_129
#define MUL mzd_mul_v_uint64_129
#define XOR mzd_xor_uint64_192
#define COPY mzd_copy_uint64_192
#define MPC_MUL mpc_matrix_mul_uint64_129

#define LOWMC_INSTANCE lowmc_129_129_4
#define LOWMC_N LOWMC_129_129_4_N
#define LOWMC_R LOWMC_129_129_4_R
#define LOWMC_M LOWMC_129_129_4_M

/*
 *   LowMC implementation (previously in lowmc_impl.c.i)
 */
//#define SBOX_FUNC CONCAT(sbox, CONCAT(IMPL, LOWMC_INSTANCE))
#define SBOX_FUNC sbox_uint64_lowmc_129_129_4
#define SBOX(x) SBOX_FUNC(BLOCK(x, 0))
#if defined(FN_ATTR)
FN_ATTR
#endif
#if defined(RECORD_STATE)
void lowmc_uint64_lowmc_129_129_4(lowmc_key_t const* lowmc_key, mzd_local_t const* p, recorded_state_t* state) {
#else
void lowmc_uint64_lowmc_129_129_4(lowmc_key_t const* lowmc_key, mzd_local_t const* p, mzd_local_t* c) {
#endif
  mzd_local_t x[((LOWMC_N) + 255) / 256];
  mzd_local_t y[((LOWMC_N) + 255) / 256];

  COPY(x, p);
  ADDMUL(x, lowmc_key, LOWMC_INSTANCE.k0_matrix);

  lowmc_round_t const* round = LOWMC_INSTANCE.rounds;
  for (unsigned i = 0; i < LOWMC_R; ++i, ++round) {
#if defined(RECORD_STATE)
    COPY(state[i].state, x);
#endif
    SBOX(x);

    MUL(y, x, round->l_matrix);
    XOR(x, y, round->constant);
    ADDMUL(x, lowmc_key, round->k_matrix);
  }

#if defined(RECORD_STATE)
  COPY(state[LOWMC_R].state, x);
#else
  COPY(c, x);
#endif
}


/*
 *   LowMC aux implementation (previously in lowmc_impl_aux.c.i)
 */

#undef SBOX
#undef SBOX_FUNC
#define SBOX_FUNC sbox_aux_uint64_lowmc_129_129_4
#define SBOX(x, y, tapes) SBOX_FUNC(BLOCK(x, 0), BLOCK(y, 0), tapes)

#if defined(FN_ATTR)
FN_ATTR
#endif
void lowmc_compute_aux_uint64_lowmc_129_129_4(lowmc_key_t* lowmc_key, randomTape_t* tapes) {
  mzd_local_t x[((LOWMC_N) + 255) / 256] = {{{0, 0, 0, 0}}};
  mzd_local_t y[((LOWMC_N) + 255) / 256];
  mzd_local_t key0[((LOWMC_N) + 255) / 256];

  COPY(key0, lowmc_key);
  MUL(lowmc_key, key0, LOWMC_INSTANCE.ki0_matrix);

  lowmc_round_t const* round = &LOWMC_INSTANCE.rounds[LOWMC_R - 1];
  for (unsigned r = 0; r < LOWMC_R; ++r, round--) {
    ADDMUL(x, lowmc_key, round->k_matrix);
    MUL(y, x, round->li_matrix);

    // recover input masks from tapes, only in first round we use the key as input
    if (r == LOWMC_R - 1) {
      COPY(x, key0);
    } else {
      bitstream_t bs = {{tapes->parity_tapes}, LOWMC_N * 2 * (LOWMC_R - 1 - r)};
      mzd_from_bitstream(&bs, x, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    }
    tapes->pos     = LOWMC_N * 2 * (LOWMC_R - 1 - r) + LOWMC_N;
    tapes->aux_pos = LOWMC_N * (LOWMC_R - 1 - r);
    SBOX(x, y, tapes);
  }
}

void masked_lowmc_compute_aux_uint64_lowmc_129_129_4(masked_mzd_t* lowmc_key, maskedRandomTape_t* tapes) {
  masked_mzd_t x[((LOWMC_N) + 255) / 256] = {0};
  masked_mzd_t y[((LOWMC_N) + 255) / 256];
  masked_mzd_t key0[((LOWMC_N) + 255) / 256];

  masked_mzd_copy_uint64_192(key0, lowmc_key);
  masked_mzd_mul_v_uint64_129(lowmc_key, key0, LOWMC_INSTANCE.ki0_matrix);

  lowmc_round_t const* round = &LOWMC_INSTANCE.rounds[LOWMC_R - 1];
  for (unsigned r = 0; r < LOWMC_R; ++r, round--) {
    masked_mzd_addmul_v_uint64_129(x, lowmc_key, round->k_matrix);
    masked_mzd_mul_v_uint64_129(y, x, round->li_matrix);

    // recover input masks from tapes, only in first round we use the key as input
    if (r == LOWMC_R - 1) {
      masked_mzd_copy_uint64_192(x, key0);
    } else {
      size_t pos = LOWMC_N * 2 * (LOWMC_R - 1 - r);
      masked_bitstream_t bs = {{
        {{tapes->parity_tapes.shares[0]}, pos},
        {{tapes->parity_tapes.shares[1]}, pos},
      }};
      masked_mzd_from_masked_bitstream(&bs, x, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    }
    tapes->pos     = LOWMC_N * 2 * (LOWMC_R - 1 - r) + LOWMC_N;
    tapes->aux_pos = LOWMC_N * (LOWMC_R - 1 - r);
    masked_sbox_aux_uint64_lowmc_129_129_4(x, y, tapes);
  }
}


#undef N_LOWMC
#undef RECORD_STATE
#undef SBOX
#undef SBOX_FUNC
