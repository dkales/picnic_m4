/*! @file picnic3_impl.c
 *  @brief This is the main file of the signature scheme for the Picnic3
 *  parameter sets.
 *
 *  This file is part of the reference implementation of the Picnic signature
 * scheme. See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_MSC_VER)
#include <stdalign.h>
#endif

#include "bitstream.h"
#include "compat.h"
#include "io.h"
#include "picnic3_simulate.h"
#include "picnic3_types.h"

#define LOWMC_INSTANCE lowmc_129_129_4
#include "lowmc_129_129_4.h"

#define ADDMUL mzd_addmul_v_uint64_129
#define MUL mzd_mul_v_uint64_129
#define XOR mzd_xor_uint64_192

#define picnic3_mpc_sbox_bitsliced(LOWMC_N, XOR, AND, SHL, SHR, bitmask_a, bitmask_b, bitmask_c)   \
  do {                                                                                             \
    mzd_local_t a[1], b[1], c[1];                                                                  \
    /* a */                                                                                        \
    AND(a, bitmask_a, statein);                                                                    \
    /* b */                                                                                        \
    AND(b, bitmask_b, statein);                                                                    \
    /* c */                                                                                        \
    AND(c, bitmask_c, statein);                                                                    \
                                                                                                   \
    SHL(a, a, 2);                                                                                  \
    SHL(b, b, 1);                                                                                  \
                                                                                                   \
    mzd_local_t t0[1], t1[1], t2[1];                                                               \
                                                                                                   \
    mzd_local_t s_ab[1], s_bc[1], s_ca[1];                                                         \
    /* b & c */                                                                                    \
    AND(s_bc, b, c);                                                                               \
    /* c & a */                                                                                    \
    AND(s_ca, c, a);                                                                               \
    /* a & b */                                                                                    \
    AND(s_ab, a, b);                                                                               \
    for (int i = 0; i < 16; i++) {                                                                 \
      mzd_local_t tmp[1];                                                                          \
      bitstream_t party_msgs = {{msgs->msgs[i]}, msgs->pos};                                       \
      if (i == msgs->unopened) {                                                                   \
        /* we are in verify, just grab the broadcast s from the msgs array */                      \
        mzd_from_bitstream(&party_msgs, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);    \
        /* a */                                                                                    \
        AND(t0, bitmask_a, tmp);                                                                   \
        /* b */                                                                                    \
        AND(t1, bitmask_b, tmp);                                                                   \
        /* c */                                                                                    \
        AND(t2, bitmask_c, tmp);                                                                   \
        SHL(t0, t0, 2);                                                                            \
        SHL(t1, t1, 1);                                                                            \
        XOR(s_ab, t2, s_ab);                                                                       \
        XOR(s_bc, t1, s_bc);                                                                       \
        XOR(s_ca, t0, s_ca);                                                                       \
                                                                                                   \
        continue;                                                                                  \
      }                                                                                            \
      bitstream_t party_tape = {{tapes->tape[i]}, tapes->pos};                                     \
      /* make a mzd_local from tape[i] for input_masks */                                          \
      mzd_local_t mask_a[1], mask_b[1], mask_c[1];                                                 \
      mzd_from_bitstream(&party_tape, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);      \
      /* a */                                                                                      \
      AND(mask_a, bitmask_a, tmp);                                                                 \
      /* b */                                                                                      \
      AND(mask_b, bitmask_b, tmp);                                                                 \
      /* c */                                                                                      \
      AND(mask_c, bitmask_c, tmp);                                                                 \
      SHL(mask_a, mask_a, 2);                                                                      \
      SHL(mask_b, mask_b, 1);                                                                      \
                                                                                                   \
      /* make a mzd_local from tape[i] for and_helper */                                           \
      mzd_local_t and_helper_ab[1], and_helper_bc[1], and_helper_ca[1];                            \
      mzd_from_bitstream(&party_tape, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);      \
      /* a */                                                                                      \
      AND(and_helper_ab, bitmask_c, tmp);                                                          \
      /* b */                                                                                      \
      AND(and_helper_bc, bitmask_b, tmp);                                                          \
      /* c */                                                                                      \
      AND(and_helper_ca, bitmask_a, tmp);                                                          \
      SHL(and_helper_ca, and_helper_ca, 2);                                                        \
      SHL(and_helper_bc, and_helper_bc, 1);                                                        \
                                                                                                   \
      /* s_ab */                                                                                   \
      AND(t0, a, mask_b);                                                                          \
      AND(t1, b, mask_a);                                                                          \
      XOR(t0, t0, t1);                                                                             \
      XOR(tmp, t0, and_helper_ab);                                                                 \
      XOR(s_ab, tmp, s_ab);                                                                        \
      /* s_bc */                                                                                   \
      AND(t0, b, mask_c);                                                                          \
      AND(t1, c, mask_b);                                                                          \
      XOR(t0, t0, t1);                                                                             \
      XOR(t0, t0, and_helper_bc);                                                                  \
      XOR(s_bc, t0, s_bc);                                                                         \
                                                                                                   \
      SHR(t0, t0, 1);                                                                              \
      XOR(tmp, tmp, t0);                                                                           \
      /* s_ca */                                                                                   \
      AND(t0, c, mask_a);                                                                          \
      AND(t1, a, mask_c);                                                                          \
      XOR(t0, t0, t1);                                                                             \
      XOR(t0, t0, and_helper_ca);                                                                  \
      XOR(s_ca, t0, s_ca);                                                                         \
                                                                                                   \
      SHR(t0, t0, 2);                                                                              \
      XOR(tmp, tmp, t0);                                                                           \
      mzd_to_bitstream(&party_msgs, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);        \
    }                                                                                              \
    tapes->pos += LOWMC_N;                                                                         \
    tapes->pos += LOWMC_N;                                                                         \
    msgs->pos += LOWMC_N;                                                                          \
                                                                                                   \
    /* (b & c) ^ a */                                                                              \
    XOR(t0, s_bc, a);                                                                              \
                                                                                                   \
    /* (c & a) ^ a ^ b */                                                                          \
    XOR(a, a, b);                                                                                  \
    XOR(t1, s_ca, a);                                                                              \
                                                                                                   \
    /* (a & b) ^ a ^ b ^c */                                                                       \
    XOR(t2, s_ab, a);                                                                              \
    XOR(t2, t2, c);                                                                                \
                                                                                                   \
    SHR(t0, t0, 2);                                                                                \
    SHR(t1, t1, 1);                                                                                \
                                                                                                   \
    XOR(t2, t2, t1);                                                                               \
    XOR(statein, t2, t0);                                                                          \
  } while (0)


static void picnic3_mpc_sbox_uint64_lowmc_129_129_4(mzd_local_t* statein, randomTape_t* tapes,
                                                    msgs_t* msgs) {

  picnic3_mpc_sbox_bitsliced(LOWMC_129_129_4_N, mzd_xor_uint64_192, mzd_and_uint64_192,
                             mzd_shift_left_uint64_192, mzd_shift_right_uint64_192,
                             mask_129_129_43_a, mask_129_129_43_b, mask_129_129_43_c);
}

#if defined(FN_ATTR)
FN_ATTR
#endif

int lowmc_simulate_online_uint64_129_43(mzd_local_t* maskedKey, randomTape_t* tapes, msgs_t* msgs,
               const mzd_local_t* plaintext, const uint8_t* pubKey) {

  int ret = 0;
  mzd_local_t state[(LOWMC_N + 255) / 256];
  mzd_local_t temp[(LOWMC_N + 255) / 256];

  MUL(temp, maskedKey, LOWMC_INSTANCE.k0_matrix);
  XOR(state, temp, plaintext);

  for (uint32_t r = 0; r < LOWMC_R; r++) {
    picnic3_mpc_sbox_uint64_lowmc_129_129_4(state, tapes, msgs);
    MUL(temp, state, LOWMC_INSTANCE.rounds[r].l_matrix);
    XOR(state, temp, LOWMC_INSTANCE.rounds[r].constant);
    ADDMUL(state, maskedKey, LOWMC_INSTANCE.rounds[r].k_matrix);
  }

  /* check that the output is correct */
  uint8_t output[MAX_LOWMC_BLOCK_SIZE] = {0};
  mzd_to_char_array(output, state, PICNIC_OUTPUT_SIZE);

  if (memcmp(output, pubKey, PICNIC_OUTPUT_SIZE) != 0) {
#if !defined(NDEBUG)
    printf("%s: output does not match pubKey\n", __func__);
    printf("pubKey: ");
    print_hex(stdout, pubKey, PICNIC_OUTPUT_SIZE);
    printf("\noutput: ");
    print_hex(stdout, output, PICNIC_OUTPUT_SIZE);
    printf("\n");
#endif
    ret = -1;
  }
  return ret;
}

#if 0  // DEBUG version that just reconstructs and uses the unprotected version
int masked_lowmc_simulate_online_uint64_129_43(masked_mzd_t* maskedKey, randomTape_t* tapes, msgs_t* msgs,
               const mzd_local_t* plaintext, const uint8_t* pubKey) {
  mzd_local_t maskedKey_unshared[1];
  mzd_reconstruct(maskedKey_unshared, maskedKey);

  return lowmc_simulate_online_uint64_129_43(maskedKey_unshared, tapes, msgs, plaintext, pubKey);
}
#endif 


#undef ADDMUL
#undef MUL
#undef XOR
#define ADDMUL masked_mzd_addmul_v_uint64_129
#define MUL masked_mzd_mul_v_uint64_129
#define XOR masked_mzd_xor_uint64_192
#define XORC masked_mzd_xorconstant_uint64_192
#define AND masked_mzd_and_uint64_192
#define ANDC masked_mzd_andconstant_uint64_192
#define SHL masked_mzd_shift_left_uint64_192
#define SHR masked_mzd_shift_right_uint64_192

#if 1
static void masked_picnic3_mpc_sbox_uint64_lowmc_129_129_4(masked_mzd_t* statein, maskedRandomTape_t* tapes,
                                                    maskedMsgs_t* msgs) {

  const mzd_local_t* bitmask_a = mask_129_129_43_a;
  const mzd_local_t* bitmask_b = mask_129_129_43_b;
  const mzd_local_t* bitmask_c = mask_129_129_43_c;

  masked_mzd_t a[1], b[1], c[1];
  /* a */
  ANDC(a, statein, bitmask_a);
  /* b */
  ANDC(b, statein, bitmask_b);
  /* c */
  ANDC(c, statein, bitmask_c);

  SHL(a, a, 2);
  SHL(b, b, 1);

  masked_mzd_t t0[1], t1[1], t2[1];
  masked_mzd_t s_ab[1], s_bc[1], s_ca[1];
  /* b & c */
  AND(s_bc, b, c);
  /* c & a */
  AND(s_ca, c, a);
  /* a & b */
  AND(s_ab, a, b);
  for (int i = 0; i < 16; i++) {
    masked_mzd_t tmp[1];
    masked_bitstream_t party_msgs = {{
      {{msgs->msgs[i].shares[0]}, msgs->pos},
      {{msgs->msgs[i].shares[1]}, msgs->pos}
    }};
    assert(i != msgs->unopened);  /* fail if this code is called from verify */

    masked_bitstream_t party_tape = {{
      {{tapes->tape[i].shares[0]}, tapes->pos}, 
      {{tapes->tape[i].shares[1]}, tapes->pos}    
    }};

    /* make a mzd_local from tape[i] for input_masks */
    masked_mzd_t mask_a[1], mask_b[1], mask_c[1];
    masked_mzd_from_masked_bitstream(&party_tape, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    /* a */
    ANDC(mask_a, tmp, bitmask_a);
    /* b */
    ANDC(mask_b, tmp, bitmask_b);
    /* c */
    ANDC(mask_c, tmp, bitmask_c);
    SHL(mask_a, mask_a, 2);
    SHL(mask_b, mask_b, 1);

    /* make a mzd_local from tape[i] for and_helper */
    masked_mzd_t and_helper_ab[1], and_helper_bc[1], and_helper_ca[1];
    masked_mzd_from_masked_bitstream(&party_tape, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
    /* a */
    ANDC(and_helper_ab, tmp, bitmask_c);
    /* b */
    ANDC(and_helper_bc, tmp, bitmask_b);
    /* c */
    ANDC(and_helper_ca, tmp, bitmask_a);
    SHL(and_helper_ca, and_helper_ca, 2);
    SHL(and_helper_bc, and_helper_bc, 1);

    /* s_ab */
    AND(t0, a, mask_b);
    AND(t1, b, mask_a);
    XOR(t0, t0, t1);
    XOR(tmp, t0, and_helper_ab);
    XOR(s_ab, tmp, s_ab);
    /* s_bc */
    AND(t0, b, mask_c);
    AND(t1, c, mask_b);
    XOR(t0, t0, t1);
    XOR(t0, t0, and_helper_bc);
    XOR(s_bc, t0, s_bc);

    SHR(t0, t0, 1);
    XOR(tmp, tmp, t0);
    /* s_ca */
    AND(t0, c, mask_a);
    AND(t1, a, mask_c);
    XOR(t0, t0, t1);
    XOR(t0, t0, and_helper_ca);
    XOR(s_ca, t0, s_ca);

    SHR(t0, t0, 2);
    XOR(tmp, tmp, t0);
    masked_mzd_to_masked_bitstream(&party_msgs, tmp, (LOWMC_N + 63) / (sizeof(uint64_t) * 8), LOWMC_N);
  }
  tapes->pos += LOWMC_N;
  tapes->pos += LOWMC_N;
  msgs->pos += LOWMC_N;

  /* (b & c) ^ a */
  XOR(t0, s_bc, a);

  /* (c & a) ^ a ^ b */
  XOR(a, a, b);
  XOR(t1, s_ca, a);

  /* (a & b) ^ a ^ b ^c */
  XOR(t2, s_ab, a);
  XOR(t2, t2, c);

  SHR(t0, t0, 2);
  SHR(t1, t1, 1);

  XOR(t2, t2, t1);
  XOR(statein, t2, t0);
}
#endif


int masked_lowmc_simulate_online_uint64_129_43(masked_mzd_t* maskedKey, maskedRandomTape_t* tapes, maskedMsgs_t* msgs,
               const mzd_local_t* plaintext, const uint8_t* pubKey) {

  int ret = 0;
  masked_mzd_t state[(LOWMC_N + 255) / 256];
  masked_mzd_t temp[(LOWMC_N + 255) / 256];
  masked_mzd_t plaintext_masked[1];

  masked_mzd_refresh(maskedKey);

  mzd_copy_uint64_192(&plaintext_masked->shares[0], plaintext); // Not really masking it, since it's public, just encoding with the masked data type
  memset(&plaintext_masked->shares[1], 0x00, sizeof(mzd_local_t));

  MUL(temp, maskedKey, LOWMC_INSTANCE.k0_matrix);
  XOR(state, temp, plaintext_masked);
  masked_mzd_refresh(state);
  masked_mzd_print("state0", state, PICNIC_INPUT_SIZE);

  for (uint32_t r = 0; r < LOWMC_R; r++) {
    masked_picnic3_mpc_sbox_uint64_lowmc_129_129_4(state, tapes, msgs);   
    masked_mzd_print("state", state, PICNIC_INPUT_SIZE);  

    MUL(temp, state, LOWMC_INSTANCE.rounds[r].l_matrix);
    masked_mzd_print("temp", temp, PICNIC_INPUT_SIZE);          
    XORC(state, temp, LOWMC_INSTANCE.rounds[r].constant);  
    masked_mzd_print("state-1", state, PICNIC_INPUT_SIZE);      
    ADDMUL(state, maskedKey, LOWMC_INSTANCE.rounds[r].k_matrix);
    masked_mzd_print("state-2", state, PICNIC_INPUT_SIZE);          
    masked_mzd_refresh(state);
  }
  

  /* check that the output is correct */
  uint8_t output[PICNIC_OUTPUT_SIZE];
  masked_mzd_to_unmasked_char_array(output, state, PICNIC_OUTPUT_SIZE);

  if (timingsafe_bcmp(output, pubKey, PICNIC_OUTPUT_SIZE) != 0) {
#if !defined(NDEBUG)
    printf("%s: output does not match pubKey\n", __func__);
    printf("pubKey: ");
    print_hex(stdout, pubKey, PICNIC_OUTPUT_SIZE);
    printf("\noutput: ");
    print_hex(stdout, output, PICNIC_OUTPUT_SIZE);
    printf("\n");
#endif
    ret = -1;
  }
  return ret;
}


