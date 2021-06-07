/*! @file picnic3_impl.c
 *  @brief This is the main file of the signature scheme for the Picnic3
 *  parameter sets.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "io.h"
#include "kdf_shake.h"
#include "lowmc.h"
#include "macros.h"
#include "picnic.h"
#include "picnic3_impl.h"
#include "picnic3_simulate.h"
#include "picnic3_tree.h"
#include "picnic3_types.h"
#include "randomness.h"

/* Helper functions */

ATTR_CONST
static uint32_t numBytes(uint32_t numBits) {
  return (numBits + 7) >> 3;
}

/* A helper while debugging */
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

static void xor_byte_array(uint8_t* out, const uint8_t* in1, const uint8_t* in2, uint32_t length) {
  for (uint32_t i = 0; i < length; i++) {
    out[i] = in1[i] ^ in2[i];
  }
}

static void masked_xor_byte_array(masked_uint8_t* out, const masked_uint8_t* in1, const masked_uint8_t* in2) {
  xor_byte_array((uint8_t*)out->shares, (uint8_t*)in1->shares, (uint8_t*)in2->shares, PICNIC_INPUT_SIZE*MASKING_T);
}

/* Set a specific bit in a masked byte array to zero */
static inline void maskedSetBitZero(masked_uint8_t* bytes, size_t bitNumber) {
  for(uint32_t j = 0; j < MASKING_T; j++) {
    setBit(bytes->shares[j], bitNumber, 0);
  }
}

/* Reconstruct a t-shared value. output parameter must have length PICNIC_INPUT_SIZE */
static inline void maskedReconstruct(uint8_t* unshared, const masked_uint8_t* shared) {
  memcpy(unshared, shared->shares[0], PICNIC_INPUT_SIZE);
  for(uint32_t j = 1; j < MASKING_T; j++) {
    xor_byte_array(unshared, unshared, shared->shares[j], PICNIC_INPUT_SIZE);
  }
}
static inline void maskedShare(masked_uint8_t* shared, const uint8_t* unshared) {
  assert(MASKING_T==2);
  memset(shared, 0x00, sizeof(masked_uint8_t));
  rand_mask(shared->shares[0], PICNIC_INPUT_SIZE);
  xor_byte_array(shared->shares[1], shared->shares[0], unshared, PICNIC_INPUT_SIZE);
}

#if 0
static inline void maskedCopy(masked_uint8_t* dst, masked_uint8_t* src) {
  memcpy((uint8_t*)dst->shares, (uint8_t*)src->shares, PICNIC_INPUT_SIZE*MASKING_T);
}
#endif

static void createRandomTapes(randomTape_t* tapes, uint8_t** seeds, uint8_t* salt, size_t t) {
  hash_context ctx;

  tapes->pos     = 0;
  tapes->aux_pos = 0;

  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    hash_init(&ctx, PICNIC_DIGEST_SIZE);

    hash_update(&ctx, seeds[i], PICNIC_SEED_SIZE);
    hash_update(&ctx, salt, PICNIC_SALT_SIZE);
    hash_update_uint16_le(&ctx, t);
    hash_update_uint16_le(&ctx, i);
    hash_final(&ctx);

    hash_squeeze(&ctx, tapes->tape[i], PICNIC_TAPE_SIZE);
  }
}

static void maskedCreateRandomTapes(maskedRandomTape_t* tapes, uint8_t** seeds, uint8_t* salt, size_t t) {
  masked_hash_context ctx;
  uint8_t seed_share[2 * PICNIC_SEED_SIZE] = { 0 };
  uint8_t salt_share[2 * PICNIC_SALT_SIZE] = { 0 };
  uint16_t zero = 0;

  tapes->pos     = 0;
  tapes->aux_pos = 0;

  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    masked_hash_init(&ctx, PICNIC_DIGEST_SIZE, MASKING_T);

#ifdef KECCAK_MASK_PUBLIC
    rand_mask(seed_share, PICNIC_SEED_SIZE);
    rand_mask(salt_share, PICNIC_SALT_SIZE);
    xor_byte_array(seed_share + PICNIC_SEED_SIZE, seed_share, seeds[i], PICNIC_SEED_SIZE);
    xor_byte_array(salt_share + PICNIC_SALT_SIZE, salt_share, salt, PICNIC_SALT_SIZE);
    rand_mask((uint8_t *)&zero, sizeof(zero));
#else
    memcpy(seed_share, seeds[i], PICNIC_SEED_SIZE);
    memcpy(salt_share, salt, PICNIC_SALT_SIZE);
#endif

    const uint8_t* seed_shares[2] = {seed_share, seed_share + PICNIC_SEED_SIZE};
    masked_hash_update(&ctx, seed_shares, PICNIC_SEED_SIZE);
    const uint8_t* salt_shares[2] = {salt_share, salt_share + PICNIC_SALT_SIZE};
    masked_hash_update(&ctx, salt_shares, PICNIC_SALT_SIZE);

    t ^= zero;
    uint16_t* uint16_shares[2] = {(uint16_t *)&t, &zero};
    masked_hash_update_uint16_le(&ctx, uint16_shares);
    t ^= zero;

    i ^= zero;
    uint16_shares[0] = (uint16_t *)&i;
    masked_hash_update_uint16_le(&ctx, uint16_shares);
    i ^= zero;

    masked_hash_final(&ctx);
    uint8_t* tape_shares[2] = {tapes->tape[i].shares[0], tapes->tape[i].shares[1]};
    masked_hash_squeeze(&ctx, tape_shares, PICNIC_TAPE_SIZE);
  }
}

/* Input is the tapes for one parallel repitition; i.e., tapes[t]
 * Updates the random tapes of all players with the mask values for the output of
 * AND gates, and computes the N-th party's share such that the AND gate invariant
 * holds on the mask values.
 */
static void computeAuxTape(randomTape_t* tapes, uint8_t* input_masks) {
  mzd_local_t lowmc_key[1];

  // combine into key shares and calculate lowmc evaluation in plain
  memset(tapes->parity_tapes, 0, PICNIC_TAPE_SIZE);
  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    for (size_t j = 0; j < PICNIC_TAPE_SIZE; j++) {
      tapes->parity_tapes[j] ^= tapes->tape[i][j];
    }
  }
  mzd_from_char_array(lowmc_key, tapes->parity_tapes, PICNIC_INPUT_SIZE);
  tapes->pos     = LOWMC_N;
  tapes->aux_pos = 0;
  memset(tapes->aux_bits, 0, PICNIC_VIEW_SIZE);

  lowmc_compute_aux_implementation_f lowmc_aux_impl = lowmc_compute_aux_uint64_lowmc_129_129_4;
  // Perform LowMC evaluation and fix AND masks for all AND gates
  lowmc_aux_impl(lowmc_key, tapes);

  // write the key masks to the input
  if (input_masks != NULL) {
    mzd_to_char_array(input_masks, lowmc_key, PICNIC_INPUT_SIZE);
  }

  // Reset the random tape counter so that the online execution uses the
  // same random bits as when computing the aux shares
  tapes->pos = 0;
}

static void maskedComputeAuxTape(maskedRandomTape_t* tapes, masked_uint8_t* input_masks) {
  masked_mzd_t lowmc_key[1];
  memset(input_masks, 0x00, sizeof(masked_uint8_t));

  // combine into key shares and calculate lowmc evaluation in plain
  memset(&tapes->parity_tapes, 0, sizeof(masked_tape_t));
  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    for (size_t j = 0; j < PICNIC_TAPE_SIZE; j++) {
      tapes->parity_tapes.shares[0][j] ^= tapes->tape[i].shares[0][j];
      tapes->parity_tapes.shares[1][j] ^= tapes->tape[i].shares[1][j];
    }
  }

  masked_mzd_from_masked_tape(lowmc_key, &tapes->parity_tapes, PICNIC_INPUT_SIZE);

  tapes->pos     = LOWMC_N;
  tapes->aux_pos = 0;
  memset(&tapes->aux_bits, 0, sizeof(masked_aux_t));

  // Perform LowMC evaluation and fix AND masks for all AND gates
  masked_lowmc_compute_aux_uint64_lowmc_129_129_4(lowmc_key, tapes);

  // write the key masks to the input
  if (input_masks != NULL) {
    masked_mzd_to_char_array(input_masks, lowmc_key, PICNIC_INPUT_SIZE);
  }

  // Reset the random tape counter so that the online execution uses the
  // same random bits as when computing the aux shares
  tapes->pos = 0;
}

static void commit(uint8_t* digest, const uint8_t* seed, const uint8_t* aux, const uint8_t* salt,
                   size_t t, size_t j) {
  /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional */
  hash_context ctx;

  hash_init(&ctx, PICNIC_DIGEST_SIZE);
  hash_update(&ctx, seed, PICNIC_SEED_SIZE);
  if (aux != NULL) {
    hash_update(&ctx, aux, PICNIC_VIEW_SIZE);
  }
  hash_update(&ctx, salt, PICNIC_SALT_SIZE);
  hash_update_uint16_le(&ctx, t);
  hash_update_uint16_le(&ctx, j);
  hash_final(&ctx);
  hash_squeeze(&ctx, digest, PICNIC_DIGEST_SIZE);
}

static void maskedCommit(uint8_t* digest, const uint8_t* seed, masked_aux_t* aux, const uint8_t* salt,
                   size_t t, size_t j) {
  /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional */
  masked_hash_context ctx;
  uint8_t slab[64];
  uint8_t* digestShares[2] = {slab, slab+32};
  uint8_t seed_share[2 * PICNIC_SEED_SIZE] = { 0 };
  uint8_t salt_share[2 * PICNIC_SALT_SIZE] = { 0 };
  uint16_t zero = 0;

  if(aux == NULL) {
    // In this case there is no masking, since aux is the only input that might be t-shared.
    commit(digest, seed, NULL, salt, t, j);
    return;
  }

#ifdef KECCAK_MASK_PUBLIC
  rand_mask(seed_share, PICNIC_SEED_SIZE);
  rand_mask(salt_share, PICNIC_SALT_SIZE);
  xor_byte_array(seed_share + PICNIC_SEED_SIZE, seed_share, seed, PICNIC_SEED_SIZE);
  xor_byte_array(salt_share + PICNIC_SALT_SIZE, salt_share, salt, PICNIC_SALT_SIZE);
  rand_mask((uint8_t *)&zero, 2);
#else
  memcpy(seed_share, seed, PICNIC_SEED_SIZE);
  memcpy(salt_share, salt, PICNIC_SALT_SIZE);
#endif

  masked_hash_init(&ctx, PICNIC_DIGEST_SIZE, MASKING_T);

  const uint8_t* seed_shares[2] = {seed_share, seed_share + PICNIC_SEED_SIZE};
  masked_hash_update(&ctx, seed_shares, PICNIC_SEED_SIZE);
  if (aux != NULL) {
    const uint8_t* aux_shares[2] = {aux->shares[0], aux->shares[1]};
	masked_hash_update(&ctx, aux_shares, PICNIC_AUX_SIZE);
  }

  const uint8_t* salt_shares[2] = {salt_share, salt_share + PICNIC_SALT_SIZE};
  masked_hash_update(&ctx, salt_shares, PICNIC_SALT_SIZE);

  t ^= zero;
  uint16_t* uint16_shares[2] = {(uint16_t *)&t, &zero};
  masked_hash_update_uint16_le(&ctx, uint16_shares);
  t ^= zero;

  j ^= zero;
  uint16_shares[0] = (uint16_t *)&j;
  masked_hash_update_uint16_le(&ctx, uint16_shares);
  j ^= zero;

  masked_hash_final(&ctx);
  masked_hash_squeeze(&ctx, digestShares, PICNIC_DIGEST_SIZE);
  xor_byte_array(digest, digestShares[0], digestShares[1], PICNIC_DIGEST_SIZE);
}

static void commit_h(uint8_t* digest, const party_commitments_t* C) {
  hash_context ctx;

  hash_init(&ctx, PICNIC_DIGEST_SIZE);
  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    hash_update(&ctx, C->hashes[i], PICNIC_DIGEST_SIZE);
  }
  hash_final(&ctx);
  hash_squeeze(&ctx, digest, PICNIC_DIGEST_SIZE);
}

// Commit to the views for one parallel rep
static void commit_v(uint8_t* digest, const uint8_t* input, const msgs_t* msgs) {
  hash_context ctx;

  hash_init(&ctx, PICNIC_DIGEST_SIZE);
  hash_update(&ctx, input, PICNIC_INPUT_SIZE);
  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    hash_update(&ctx, msgs->msgs[i], numBytes(msgs->pos));
  }
  hash_final(&ctx);
  hash_squeeze(&ctx, digest, PICNIC_DIGEST_SIZE);
}

static void maskedCommit_v(uint8_t* digest, const masked_uint8_t* input, const maskedMsgs_t* msgs) {
  masked_hash_context ctx;
  uint8_t slab[64];
  uint8_t* digestShares[2] = {slab, slab+32};

  masked_hash_init(&ctx, PICNIC_DIGEST_SIZE, MASKING_T);
  const uint8_t* input_shares[2] = {input->shares[0], input->shares[1]};
  masked_hash_update(&ctx, input_shares, PICNIC_INPUT_SIZE);
  for (size_t i = 0; i < PICNIC_NUM_PARTIES; i++) {
    const uint8_t* msgs_shares[2] = {msgs->msgs[i].shares[0], msgs->msgs[i].shares[1]};
    masked_hash_update(&ctx, msgs_shares, numBytes(msgs->pos));
  }
  masked_hash_final(&ctx);

  masked_hash_squeeze(&ctx, digestShares, PICNIC_DIGEST_SIZE);
  xor_byte_array(digest, digestShares[0], digestShares[1], PICNIC_DIGEST_SIZE);
}

static int contains(const uint16_t* list, size_t len, uint16_t value) {
  for (size_t i = 0; i < len; i++) {
    if (list[i] == value) {
      return 1;
    }
  }
  return 0;
}

static int indexOf(const uint16_t* list, size_t len, uint16_t value) {
  for (size_t i = 0; i < len; i++) {
    if (list[i] == value) {
      return i;
    }
  }
  assert(!"indexOf called on list where value is not found. (caller bug)");
  return -1;
}

static void setAuxBits(randomTape_t* tapes, uint8_t* input) {
  size_t last  = PICNIC_NUM_PARTIES - 1;
  size_t inBit = 0;

  for (size_t j = 0; j < LOWMC_R; j++) {
    for (size_t i = 0; i < LOWMC_N; i++) {
      setBit(tapes->tape[last], LOWMC_N + LOWMC_N * 2 * (j) + i, getBit(input, inBit++));
    }
  }
}

static size_t bitsToChunks(size_t chunkLenBits, const uint8_t* input, size_t inputLen,
                           uint16_t* chunks) {
  if (chunkLenBits > inputLen * 8) {
    assert(!"Invalid input to bitsToChunks: not enough input");
    return 0;
  }
  size_t chunkCount = ((inputLen * 8) / chunkLenBits);

  for (size_t i = 0; i < chunkCount; i++) {
    chunks[i] = 0;
    for (size_t j = 0; j < chunkLenBits; j++) {
      chunks[i] += getBit(input, i * chunkLenBits + j) << j;
      assert(chunks[i] < (1 << chunkLenBits));
    }
  }

  return chunkCount;
}

static size_t appendUnique(uint16_t* list, uint16_t value, size_t position) {
  if (position == 0) {
    list[position] = value;
    return position + 1;
  }

  for (size_t i = 0; i < position; i++) {
    if (list[i] == value) {
      return position;
    }
  }
  list[position] = value;
  return position + 1;
}

static void expandChallenge(uint16_t* challengeC, uint16_t* challengeP, const uint8_t* sigH) {
  uint8_t h[PICNIC_DIGEST_SIZE] = {0};
  hash_context ctx;

  memcpy(h, sigH, PICNIC_DIGEST_SIZE);
  // Populate C
  uint32_t bitsPerChunkC = ceil_log2(PICNIC_NUM_ROUNDS);
  uint32_t bitsPerChunkP = ceil_log2(PICNIC_NUM_PARTIES);
  uint16_t chunks[PICNIC_DIGEST_SIZE * 8 / MIN(PICNIC_NUM_PARTIES_LOG2, PICNIC_NUM_ROUNDS_LOG2)] = {
      0,
  };

  size_t countC = 0;
  while (countC < PICNIC_NUM_OPENED_ROUNDS) {
    size_t numChunks = bitsToChunks(bitsPerChunkC, h, PICNIC_DIGEST_SIZE, chunks);
    for (size_t i = 0; i < numChunks; i++) {
      if (chunks[i] < PICNIC_NUM_ROUNDS) {
        countC = appendUnique(challengeC, chunks[i], countC);
      }
      if (countC == PICNIC_NUM_OPENED_ROUNDS) {
        break;
      }
    }

    hash_init_prefix(&ctx, PICNIC_DIGEST_SIZE, HASH_PREFIX_1);
    hash_update(&ctx, h, PICNIC_DIGEST_SIZE);
    hash_final(&ctx);
    hash_squeeze(&ctx, h, PICNIC_DIGEST_SIZE);
  }

  // Note that we always compute h = H(h) after setting C
  size_t countP = 0;

  while (countP < PICNIC_NUM_OPENED_ROUNDS) {
    size_t numChunks = bitsToChunks(bitsPerChunkP, h, PICNIC_DIGEST_SIZE, chunks);
    for (size_t i = 0; i < numChunks; i++) {
      if (chunks[i] < PICNIC_NUM_PARTIES) {
        challengeP[countP] = chunks[i];
        countP++;
      }
      if (countP == PICNIC_NUM_OPENED_ROUNDS) {
        break;
      }
    }

    hash_init_prefix(&ctx, PICNIC_DIGEST_SIZE, HASH_PREFIX_1);
    hash_update(&ctx, h, PICNIC_DIGEST_SIZE);
    hash_final(&ctx);
    hash_squeeze(&ctx, h, PICNIC_DIGEST_SIZE);
  }
}

static void HCP(uint8_t* sigH, uint16_t* challengeC, uint16_t* challengeP, round_commitments_t* Ch,
                uint8_t* hCv, uint8_t* salt, const uint8_t* pubKey, const uint8_t* plaintext,
                const uint8_t* message, size_t messageByteLength) {
  hash_context ctx;

  assert(PICNIC_NUM_OPENED_ROUNDS < PICNIC_NUM_ROUNDS);

  hash_init(&ctx, PICNIC_DIGEST_SIZE);
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    hash_update(&ctx, Ch->hashes[t], PICNIC_DIGEST_SIZE);
  }

  hash_update(&ctx, hCv, PICNIC_DIGEST_SIZE);
  hash_update(&ctx, salt, PICNIC_SALT_SIZE);
  hash_update(&ctx, pubKey, PICNIC_INPUT_SIZE);
  hash_update(&ctx, plaintext, PICNIC_INPUT_SIZE);
  hash_update(&ctx, message, messageByteLength);
  hash_final(&ctx);
  hash_squeeze(&ctx, sigH, PICNIC_DIGEST_SIZE);
  /* parts of this hash will be published as challenge so is public anyway */
  picnic_declassify(sigH, PICNIC_DIGEST_SIZE);

  expandChallenge(challengeC, challengeP, sigH);
}

static void getMissingLeavesList(uint16_t* missingLeaves, uint16_t* challengeC) {
  size_t pos = 0;

  for (size_t i = 0; i < PICNIC_NUM_ROUNDS; i++) {
    if (!contains(challengeC, PICNIC_NUM_OPENED_ROUNDS, i)) {
      missingLeaves[pos] = i;
      pos++;
    }
  }
}

static int verify_picnic3(signature2_t* sig, const uint8_t* pubKey, const uint8_t* plaintext,
                          const uint8_t* message, size_t messageByteLength) {
  msgs_t msgs;
  memset(msgs.msgs, 0, PICNIC_VIEW_SIZE * PICNIC_NUM_PARTIES);
  tree_t treeCv;
  round_commitment_tree_storage_t treeCvStorage;
  createRoundCommitmentTree(&treeCv, &treeCvStorage);
  uint16_t challengeC[PICNIC_NUM_OPENED_ROUNDS * sizeof(uint16_t)];
  uint16_t challengeP[PICNIC_NUM_OPENED_ROUNDS * sizeof(uint16_t)];
  uint8_t challenge[PICNIC_DIGEST_SIZE];
  randomTape_t tape;
  tree_t iSeedsTree;
  round_seed_tree_storage_t iSeedsStorage;
  createRoundSeedTree(&iSeedsTree, &iSeedsStorage);
  int ret           = reconstructRoundSeeds(&iSeedsTree, sig->challengeC, PICNIC_NUM_OPENED_ROUNDS,
                                  sig->iSeedInfo, sig->iSeedInfoLen, sig->salt, 0);
  const size_t last = PICNIC_NUM_PARTIES - 1;
  lowmc_simulate_online_f simulateOnline = lowmc_simulate_online_uint64_129_43;

  party_commitments_t C;
  round_commitments_t Ch;
  round_commitments_t Cv;
  mzd_local_t m_plaintext[1];
  mzd_local_t m_maskedKey[1];
  mzd_from_char_array(m_plaintext, plaintext, PICNIC_OUTPUT_SIZE);

  if (ret != 0) {
    ret = -1;
    goto Exit;
  }

  uint8_t* Cv_hashes[PICNIC_NUM_ROUNDS]; // to be able to store NULL pointers sometimes
  for (uint32_t i = 0; i < PICNIC_NUM_ROUNDS; i++) {
    Cv_hashes[i] = Cv.hashes[i];
  }

  /* Populate seeds with values from the signature */
  size_t proof_index = 0;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    tree_t seed;
    parties_seed_tree_storage_t seedStorage;
    if (!contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      /* Expand iSeed[t] to seeds for each parties, using a seed tree */
      generatePartySeeds(&seed, &seedStorage, getLeaf(&iSeedsTree, t), sig->salt, t);
    } else {
      /* We don't have the initial seed for the round, but instead a seed
       * for each unopened party */
      createPartySeedTree(&seed, &seedStorage);
      size_t P_index = indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t);
      ret =
          reconstructPartySeeds(&seed, sig->challengeP[P_index], sig->proofs[proof_index].seedInfo,
                                sig->proofs[proof_index].seedInfoLen, sig->salt, t);
      if (ret != 0) {
#if !defined(NDEBUG)
        printf("Failed to reconstruct seeds for round " SIZET_FMT "\n", t);
#endif
        ret = -1;
        goto Exit;
      }
    }
    /* Commit */

    /* Compute random tapes for all parties.  One party for each repitition
     * challengeC will have a bogus seed; but we won't use that party's
     * random tape. */
    createRandomTapes(&tape, getLeaves(&seed), sig->salt, t);

    if (!contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      /* We're given iSeed, have expanded the seeds, compute aux from scratch so we can comnpte
       * Com[t] */
      computeAuxTape(&tape, NULL);
      for (size_t j = 0; j < last; j++) {
        commit(C.hashes[j], getLeaf(&seed, j), NULL, sig->salt, t, j);
      }
      commit(C.hashes[last], getLeaf(&seed, last), tape.aux_bits, sig->salt, t, last);
      /* after we have checked the tape, we do not need it anymore for this opened iteration */
    } else {
      /* We're given all seeds and aux bits, execpt for the unopened
       * party, we get their commitment */
      size_t unopened = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];
      for (size_t j = 0; j < last; j++) {
        commit(C.hashes[j], getLeaf(&seed, j), NULL, sig->salt, t, j);
      }
      if (last != unopened) {
        commit(C.hashes[last], getLeaf(&seed, last), sig->proofs[proof_index].aux, sig->salt, t,
               last);
      }

      memcpy(C.hashes[unopened], sig->proofs[proof_index].C, PICNIC_DIGEST_SIZE);
    }
    /* hash commitments every four iterations if possible, for the last few do single commitments
     */
    commit_h(Ch.hashes[t], &C);

    /* Commit to the views */
    if (!contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      Cv_hashes[t] = NULL;
    }
    if (contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      /* 2. When t is in C, we have everything we need to re-compute the view, as an honest signer
       * would.
       * We simulate the MPC with one fewer party; the unopned party's values are all set to zero.
       */
      size_t unopened = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];
      uint8_t* input  = sig->proofs[proof_index].input;
      setAuxBits(&tape, sig->proofs[proof_index].aux);
      memset(tape.tape[unopened], 0, 2 * PICNIC_VIEW_SIZE);
      memcpy(msgs.msgs[unopened], sig->proofs[proof_index].msgs, PICNIC_VIEW_SIZE);
      mzd_from_char_array(m_maskedKey, input, PICNIC_INPUT_SIZE);
      msgs.unopened = unopened;
      msgs.pos      = 0;
      ret           = simulateOnline(m_maskedKey, &tape, &msgs, m_plaintext, pubKey);

      if (ret != 0) {
#if !defined(NDEBUG)
        printf("MPC simulation failed for round " SIZET_FMT ", signature invalid\n", t);
#endif
        ret = -1;
        goto Exit;
      }
      commit_v(Cv.hashes[t], sig->proofs[proof_index].input, &msgs);
      proof_index++;
    }
  }

  size_t missingLeavesSize = PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS;
  uint16_t missingLeaves[PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS];
  getMissingLeavesList(missingLeaves, sig->challengeC);
  ret = addMerkleNodes(&treeCv, missingLeaves, missingLeavesSize, sig->cvInfo, sig->cvInfoLen);
  if (ret != 0) {
    ret = -1;
    goto Exit;
  }

  ret = verifyMerkleTree(&treeCv, Cv_hashes, sig->salt);
  if (ret != 0) {
    ret = -1;
    goto Exit;
  }

  /* Compute the challenge; two lists of integers */
  HCP(challenge, challengeC, challengeP, &Ch, treeCv.nodes[0], sig->salt, pubKey, plaintext,
      message, messageByteLength);

  /* Compare to challenge from signature */
  if (memcmp(sig->challenge, challenge, PICNIC_DIGEST_SIZE) != 0) {
#if !defined(NDEBUG)
    printf("Challenge does not match, signature invalid\n");
#endif
    ret = -1;
    goto Exit;
  }

  ret = EXIT_SUCCESS;

Exit:

  return ret;
}

#if 1  // There are two options for deriving the root seed.
static void maskedComputeSaltAndRootSeed(uint8_t* saltAndRoot, size_t saltAndRootLength,
                                   const masked_private_key_t* privateKey, const uint8_t* pubKey,
                                   const uint8_t* plaintext, const uint8_t* message,
                                   size_t messageByteLength) {
  masked_hash_context ctx;
  uint8_t *slab = alloca(2*saltAndRootLength);
  uint8_t* digestShares[2] = {slab, slab+saltAndRootLength};
  uint8_t *msg_shares = alloca(2 * messageByteLength);
  uint8_t pub_shares[2 * PICNIC_INPUT_SIZE] = { 0 };
  uint8_t plain_shares[2 * PICNIC_INPUT_SIZE] = { 0 };
  uint16_t zero = 0;

  masked_hash_init(&ctx, PICNIC_DIGEST_SIZE, MASKING_T);
  const uint8_t* shares[2] = {privateKey->shares[0], privateKey->shares[1]};
  masked_hash_update(&ctx, shares, PICNIC_INPUT_SIZE);

#ifdef KECCAK_MASK_PUBLIC
  rand_mask(msg_shares, messageByteLength);
  rand_mask(pub_shares, PICNIC_INPUT_SIZE);
  rand_mask(plain_shares, PICNIC_INPUT_SIZE);
  xor_byte_array(msg_shares + messageByteLength, msg_shares, message, messageByteLength);
  xor_byte_array(pub_shares + PICNIC_INPUT_SIZE, pub_shares, pubKey, PICNIC_INPUT_SIZE);
  xor_byte_array(plain_shares + PICNIC_INPUT_SIZE, plain_shares, plaintext, PICNIC_INPUT_SIZE);
  rand_mask((uint8_t *)&zero, sizeof(zero));
#else
  memcpy(msg_shares, message, messageByteLength);
  memset(msg_shares + messageByteLength, 0, messageByteLength);
  memcpy(pub_shares, pubKey, PICNIC_INPUT_SIZE);
  memcpy(plain_shares, plaintext, PICNIC_INPUT_SIZE);
#endif

  shares[0] = msg_shares;
  shares[1] = msg_shares + messageByteLength;
  masked_hash_update(&ctx, shares, messageByteLength);
  shares[0] = pub_shares;
  shares[1] = pub_shares + PICNIC_INPUT_SIZE;
  masked_hash_update(&ctx, shares, PICNIC_INPUT_SIZE);
  shares[0] = plain_shares;
  shares[1] = plain_shares + PICNIC_INPUT_SIZE;
  masked_hash_update(&ctx, shares, PICNIC_INPUT_SIZE);

  uint16_t lowmc_n = (uint16_t)LOWMC_N ^ zero;
  uint16_t* uint16_shares[2] = {(uint16_t *)&lowmc_n, &zero};
  masked_hash_update_uint16_le(&ctx, uint16_shares);

  #ifndef MASKED_IMPL_DETERMINISTIC
    /* By default, signing with the masked implementation is randomized.
     * Include 32 random bytes when deriving the salt and root seeds. */
    uint8_t R[32];
    shares[0] = R;
    shares[1] = R + 16;
    rand_bytes(R, sizeof(R));
    masked_hash_update(&ctx, shares, 16);
  #endif

  masked_hash_final(&ctx);
  masked_hash_squeeze(&ctx, digestShares, saltAndRootLength);
  xor_byte_array(saltAndRoot, digestShares[0], digestShares[1], saltAndRootLength);
}
#elif  0
// Here we can alternatively just hash all the shares.  See
// description in write-up "Deriving root seed".
// But if we make this change, out kats test program will fail; so it's below as
// an option we can benchmark, but not enabled by default.  Since this is called once
// per signature, it's simpler to just always use masked SHA-3 for this function.
// The difference was 43K cycles on our M4 board.
static void maskedComputeSaltAndRootSeed(uint8_t* saltAndRoot, size_t saltAndRootLength,
                                   const masked_private_key_t* privateKey, const uint8_t* pubKey,
                                   const uint8_t* plaintext, const uint8_t* message,
                                   size_t messageByteLength) {
  hash_context ctx;

  hash_init(&ctx, PICNIC_DIGEST_SIZE);
  hash_update(&ctx, privateKey->shares[0], PICNIC_INPUT_SIZE);
  hash_update(&ctx, privateKey->shares[1], PICNIC_INPUT_SIZE);
  hash_update(&ctx, message, messageByteLength);
  hash_update(&ctx, pubKey, PICNIC_INPUT_SIZE);
  hash_update(&ctx, plaintext, PICNIC_INPUT_SIZE);
  hash_update_uint16_le(&ctx, (uint16_t)LOWMC_N);
  hash_final(&ctx);
  hash_squeeze(&ctx, saltAndRoot, saltAndRootLength);
}
#endif

static int sign_picnic3(masked_private_key_t* privateKey, const uint8_t* pubKey, const uint8_t* plaintext,
                        const uint8_t* message, size_t messageByteLength, signature2_t* sig) {
  int ret = 0;
  uint8_t saltAndRoot[PICNIC_SEED_SIZE + PICNIC_SALT_SIZE];

  maskedComputeSaltAndRootSeed(saltAndRoot, PICNIC_SEED_SIZE + PICNIC_SALT_SIZE, privateKey, pubKey,
                         plaintext, message, messageByteLength);
  memcpy(sig->salt, saltAndRoot, PICNIC_SALT_SIZE);
  tree_t iSeedsTree;
  round_seed_tree_storage_t iSeedsTreeStorage;
  generateRoundSeeds(&iSeedsTree, &iSeedsTreeStorage, saltAndRoot + PICNIC_SALT_SIZE, sig->salt, 0);
  uint8_t** iSeeds = getLeaves(&iSeedsTree);

  maskedRandomTape_t tape;
  tree_t seed;
  parties_seed_tree_storage_t seedTreeStorage;

  masked_lowmc_simulate_online_f simulateOnline = masked_lowmc_simulate_online_uint64_129_43;
  masked_uint8_t input;
  maskedMsgs_t msgs;

  party_commitments_t C;
  /* Commitments to the commitments and views */
  round_commitments_t Ch;
  round_commitments_t Cv;

  mzd_local_t m_plaintext[1];
  masked_mzd_t m_maskedKey[1];

  mzd_from_char_array(m_plaintext, plaintext, PICNIC_OUTPUT_SIZE);

  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    generatePartySeeds(&seed, &seedTreeStorage, iSeeds[t], sig->salt, t);
    maskedCreateRandomTapes(&tape, getLeaves(&seed), sig->salt, t);
    /* Preprocessing; compute aux tape for the N-th player, for each parallel rep */
    maskedComputeAuxTape(&tape, &input);
    /* Commit to seeds and aux bits */
    const size_t last = PICNIC_NUM_PARTIES - 1;
    for (size_t j = 0; j < last; j++) {
      commit(C.hashes[j], getLeaf(&seed, j), NULL, sig->salt, t, j);
    }
    maskedCommit(C.hashes[last], getLeaf(&seed, last), &tape.aux_bits, sig->salt, t, last);

    /* Simulate the online phase of the MPC */
    masked_uint8_t* maskedKey = &input;

    masked_xor_byte_array(maskedKey, maskedKey, privateKey); // maskedKey += privateKey
    for (size_t i = LOWMC_N; i < PICNIC_INPUT_SIZE * 8; i++) {
      maskedSetBitZero(maskedKey, i);
    }

    masked_mzd_from_char_array(m_maskedKey, maskedKey, PICNIC_INPUT_SIZE);

#if PICNIC_DEBUG_TRACE
    printf("preprocessing t = %lu ", t);
    masked_mzd_print("m_maskedKey", m_maskedKey, PICNIC_INPUT_SIZE);
#endif

    msgs.pos      = 0;
    msgs.unopened = -1;
    memset(msgs.msgs, 0, sizeof(masked_view_t) * PICNIC_NUM_PARTIES);
    int rv = simulateOnline(m_maskedKey, &tape, &msgs, m_plaintext, pubKey);
    if (rv != 0) {
#if !defined(NDEBUG)
      printf("MPC simulation failed in round " SIZET_FMT ", aborting signature\n", t);
#endif
#if PICNIC_DEBUG_TRACE
  printf("Exiting\n");
  exit(0);
#endif
      ret = -1;
    }
    commit_h(Ch.hashes[t], &C);
    maskedCommit_v(Cv.hashes[t], &input, &msgs);
  }

  /* Create a Merkle tree with Cv as the leaves */
  tree_t treeCv;
  round_commitment_tree_storage_t treeCvStorage;
  createRoundCommitmentTree(&treeCv, &treeCvStorage);
  uint8_t* Cv_hashes[PICNIC_NUM_ROUNDS];
  for (uint32_t i = 0; i < PICNIC_NUM_ROUNDS; i++) {
    Cv_hashes[i] = Cv.hashes[i];
  }
  buildMerkleTree(&treeCv, Cv_hashes, sig->salt);

  /* Compute the challenge; two lists of integers */
  uint16_t* challengeC = sig->challengeC;
  uint16_t* challengeP = sig->challengeP;
  HCP(sig->challenge, challengeC, challengeP, &Ch, treeCv.nodes[0], sig->salt, pubKey, plaintext,
      message, messageByteLength);

  /* Send information required for checking commitments with Merkle tree.
   * The commitments the verifier will be missing are those not in challengeC. */
  const size_t missingLeavesSize = PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS;
  uint16_t missingLeaves[PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS];
  getMissingLeavesList(missingLeaves, challengeC);
  openMerkleTree(&treeCv, missingLeaves, missingLeavesSize, sig->cvInfo, &sig->cvInfoLen);

  /* Reveal iSeeds for unopened rounds, those in {0..T-1} \ ChallengeC. */
  sig->iSeedInfoLen = revealRoundSeeds(&iSeedsTree, challengeC, PICNIC_NUM_OPENED_ROUNDS,
                                       sig->iSeedInfo, sizeof(sig->iSeedInfo));

  /* Assemble the proof */
  size_t proof_index = 0;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    if (contains(challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      generatePartySeeds(&seed, &seedTreeStorage, iSeeds[t], sig->salt, t);
      maskedCreateRandomTapes(&tape, getLeaves(&seed), sig->salt, t);
      /* Preprocessing; compute aux tape for the N-th player, for each parallel rep */
      maskedComputeAuxTape(&tape, &input);
      /* Simulate the online phase of the MPC */
      masked_uint8_t* maskedKey = &input;

      masked_xor_byte_array(maskedKey, maskedKey, privateKey);  // maskedKey += privateKey
      for (size_t i = LOWMC_N; i < PICNIC_INPUT_SIZE * 8; i++) {
        maskedSetBitZero(maskedKey, i);
      }

      masked_mzd_from_char_array(m_maskedKey, maskedKey, PICNIC_INPUT_SIZE);

      msgs.pos      = 0;
      msgs.unopened = -1;
      memset(msgs.msgs, 0, PICNIC_VIEW_SIZE * PICNIC_NUM_PARTIES);
      int rv = simulateOnline(m_maskedKey, &tape, &msgs, m_plaintext, pubKey);
      if (rv != 0) {
#if !defined(NDEBUG)
        printf("MPC simulation failed in round " SIZET_FMT ", aborting signature\n", t);
#endif
        ret = -1;
      }

      proof2_t* proof = &sig->proofs[proof_index];
      proof_index++;
      size_t P_index       = indexOf(challengeC, PICNIC_NUM_OPENED_ROUNDS, t);
      proof->unOpenedIndex = challengeP[P_index];

      proof->seedInfoLen =
          revealPartySeeds(&seed, challengeP[P_index], proof->seedInfo, sizeof(proof->seedInfo));

      size_t last = PICNIC_NUM_PARTIES - 1;
      if (challengeP[P_index] != last) {
        xor_byte_array(tape.aux_bits.shares[0], tape.aux_bits.shares[0], tape.aux_bits.shares[1], PICNIC_AUX_SIZE); // Reconstruct before output
        memcpy(proof->aux, tape.aux_bits.shares[0], PICNIC_AUX_SIZE);
      }

      uint8_t tmp[PICNIC_INPUT_SIZE];
      maskedReconstruct(tmp, &input);   // Reconstruct the MPC input to output in proof, since t \in C
      memcpy(proof->input, tmp, PICNIC_INPUT_SIZE);

      // Reconstruct msgs for unopened party; since it's part of the signature
      xor_byte_array(proof->msgs, msgs.msgs[challengeP[P_index]].shares[0],
          msgs.msgs[challengeP[P_index]].shares[1], PICNIC_VIEW_SIZE);

      /* recompute commitment of unopened party since we did not store it for memory optimization
       */
      if (proof->unOpenedIndex == PICNIC_NUM_PARTIES - 1) {
        maskedCommit(proof->C, getLeaf(&seed, proof->unOpenedIndex), &tape.aux_bits, sig->salt, t,
               proof->unOpenedIndex);
      } else {
        commit(proof->C, getLeaf(&seed, proof->unOpenedIndex), NULL, sig->salt, t,
               proof->unOpenedIndex);
      }
    }
  }

  return ret;
}

static int arePaddingBitsZero(uint8_t* data, size_t byteLength, size_t bitLength) {
  return !check_padding_bits(data[byteLength - 1], byteLength * 8 - bitLength);
}

static int deserializeSignature2(signature2_t* sig, const uint8_t* sigBytes, size_t sigBytesLen) {
  /* Read the challenge and salt */
  size_t bytesRequired = PICNIC_DIGEST_SIZE + PICNIC_SALT_SIZE;

  if (sigBytesLen < bytesRequired) {
    return EXIT_FAILURE;
  }

  memcpy(sig->challenge, sigBytes, PICNIC_DIGEST_SIZE);
  sigBytes += PICNIC_DIGEST_SIZE;
  memcpy(sig->salt, sigBytes, PICNIC_SALT_SIZE);
  sigBytes += PICNIC_SALT_SIZE;

  expandChallenge(sig->challengeC, sig->challengeP, sig->challenge);

  /* Add size of iSeeds tree data */
  sig->iSeedInfoLen = revealRoundSeedsSize(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS);
  bytesRequired += sig->iSeedInfoLen;

  /* Add the size of the Cv Merkle tree data */
  size_t missingLeavesSize = PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS;
  uint16_t missingLeaves[PICNIC_NUM_ROUNDS - PICNIC_NUM_OPENED_ROUNDS];
  getMissingLeavesList(missingLeaves, sig->challengeC);
  sig->cvInfoLen = openMerkleTreeSize(missingLeaves, missingLeavesSize);
  bytesRequired += sig->cvInfoLen;

  /* Compute the number of bytes required for the proofs */
  size_t seedInfoLen = PICNIC_NUM_PARTIES_LOG2 * PICNIC_SEED_SIZE;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    if (contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      size_t P_t = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];
      if (P_t != (PICNIC_NUM_PARTIES - 1)) {
        bytesRequired += PICNIC_VIEW_SIZE;
      }
      bytesRequired += PICNIC_DIGEST_SIZE;
      bytesRequired += PICNIC_INPUT_SIZE;
      bytesRequired += PICNIC_VIEW_SIZE;
      bytesRequired += seedInfoLen;
    }
  }

  /* Fail if the signature does not have the exact number of bytes we expect */
  if (sigBytesLen != bytesRequired) {
#if !defined(NDEBUG)
    printf("%s: sigBytesLen = " SIZET_FMT ", expected bytesRequired = " SIZET_FMT "\n", __func__,
           sigBytesLen, bytesRequired);
#endif
    return EXIT_FAILURE;
  }

  memcpy(sig->iSeedInfo, sigBytes, sig->iSeedInfoLen);
  sigBytes += sig->iSeedInfoLen;

  memcpy(sig->cvInfo, sigBytes, sig->cvInfoLen);
  sigBytes += sig->cvInfoLen;

  /* Read the proofs */
  size_t proof_index = 0;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    if (contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      sig->proofs[proof_index].seedInfoLen = seedInfoLen;
      memcpy(sig->proofs[proof_index].seedInfo, sigBytes, sig->proofs[proof_index].seedInfoLen);
      sigBytes += sig->proofs[proof_index].seedInfoLen;

      size_t P_t = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];
      if (P_t != (PICNIC_NUM_PARTIES - 1)) {
        memcpy(sig->proofs[proof_index].aux, sigBytes, PICNIC_VIEW_SIZE);
        sigBytes += PICNIC_VIEW_SIZE;
        if (!arePaddingBitsZero(sig->proofs[proof_index].aux, PICNIC_VIEW_SIZE,
                                3 * LOWMC_R * LOWMC_M)) {
#if !defined(NDEBUG)
          printf("%s: failed while deserializing aux bits\n", __func__);
#endif
          return -1;
        }
      }

      memcpy(sig->proofs[proof_index].input, sigBytes, PICNIC_INPUT_SIZE);
      if (!arePaddingBitsZero(sig->proofs[proof_index].input, PICNIC_INPUT_SIZE, LOWMC_N)) {
#if !defined(NDEBUG)
        printf("%s: failed while deserializing input bits\n", __func__);
#endif
        return -1;
      }
      sigBytes += PICNIC_INPUT_SIZE;

      size_t msgsByteLength = PICNIC_VIEW_SIZE;
      memcpy(sig->proofs[proof_index].msgs, sigBytes, msgsByteLength);
      sigBytes += msgsByteLength;
      size_t msgsBitLength = 3 * LOWMC_R * LOWMC_M;
      if (!arePaddingBitsZero(sig->proofs[proof_index].msgs, msgsByteLength, msgsBitLength)) {
#if !defined(NDEBUG)
        printf("%s: failed while deserializing msgs bits\n", __func__);
#endif
        return -1;
      }

      memcpy(sig->proofs[proof_index].C, sigBytes, PICNIC_DIGEST_SIZE);
      sigBytes += PICNIC_DIGEST_SIZE;
      proof_index++;
    }
  }

  return EXIT_SUCCESS;
}

static int serializeSignature2(const signature2_t* sig, uint8_t* sigBytes, size_t sigBytesLen) {
  uint8_t* sigBytesBase = sigBytes;

  /* Compute the number of bytes required for the signature */
  size_t bytesRequired = PICNIC_DIGEST_SIZE + PICNIC_SALT_SIZE; /* challenge and salt */

  bytesRequired +=
      sig->iSeedInfoLen; /* Encode only iSeedInfo, the length will be recomputed by deserialize */
  bytesRequired += sig->cvInfoLen;

  size_t proof_index = 0;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) { /* proofs */
    if (contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      size_t P_t = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];
      bytesRequired += sig->proofs[proof_index].seedInfoLen;
      if (P_t != (PICNIC_NUM_PARTIES - 1)) {
        bytesRequired += PICNIC_VIEW_SIZE;
      }
      bytesRequired += PICNIC_DIGEST_SIZE;
      bytesRequired += PICNIC_INPUT_SIZE;
      bytesRequired += PICNIC_VIEW_SIZE;
      proof_index++;
    }
  }

  if (sigBytesLen < bytesRequired) {
    return -1;
  }

  memcpy(sigBytes, sig->challenge, PICNIC_DIGEST_SIZE);
  sigBytes += PICNIC_DIGEST_SIZE;

  memcpy(sigBytes, sig->salt, PICNIC_SALT_SIZE);
  sigBytes += PICNIC_SALT_SIZE;

  memcpy(sigBytes, sig->iSeedInfo, sig->iSeedInfoLen);
  sigBytes += sig->iSeedInfoLen;
  memcpy(sigBytes, sig->cvInfo, sig->cvInfoLen);
  sigBytes += sig->cvInfoLen;

  /* Write the proofs */
  proof_index = 0;
  for (size_t t = 0; t < PICNIC_NUM_ROUNDS; t++) {
    if (contains(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)) {
      memcpy(sigBytes, sig->proofs[proof_index].seedInfo, sig->proofs[proof_index].seedInfoLen);
      sigBytes += sig->proofs[proof_index].seedInfoLen;

      size_t P_t = sig->challengeP[indexOf(sig->challengeC, PICNIC_NUM_OPENED_ROUNDS, t)];

      if (P_t != (PICNIC_NUM_PARTIES - 1)) {
        memcpy(sigBytes, sig->proofs[proof_index].aux, PICNIC_VIEW_SIZE);
        sigBytes += PICNIC_VIEW_SIZE;
      }

      memcpy(sigBytes, sig->proofs[proof_index].input, PICNIC_INPUT_SIZE);
      sigBytes += PICNIC_INPUT_SIZE;

      memcpy(sigBytes, sig->proofs[proof_index].msgs, PICNIC_VIEW_SIZE);
      sigBytes += PICNIC_VIEW_SIZE;

      #if PICNIC_DEBUG_TRACE
      printf("t = %lu, P_t = %lu\n", t, P_t);
        if(P_t != 15)
          printHex("aux", sig->proofs[proof_index].aux, PICNIC_VIEW_SIZE);
        printHex("input", sig->proofs[proof_index].input, PICNIC_INPUT_SIZE);
        printHex("msgs", sig->proofs[proof_index].msgs, PICNIC_VIEW_SIZE);
      #endif

      memcpy(sigBytes, sig->proofs[proof_index].C, PICNIC_DIGEST_SIZE);
      sigBytes += PICNIC_DIGEST_SIZE;
      proof_index++;
    }
  }

  return (int)(sigBytes - sigBytesBase);
}

int impl_sign_picnic3(const uint8_t* plaintext, const uint8_t* private_key,
                      const uint8_t* public_key, const uint8_t* msg, size_t msglen,
                      uint8_t* signature, size_t* signature_len) {
  signature2_t sig;
  masked_private_key_t masked_sk = {0};
  maskedShare(&masked_sk, private_key);   // This is where we start masking in this implementation

  int ret = sign_picnic3(&masked_sk, public_key, plaintext, msg, msglen, &sig);
  picnic_declassify(&ret, sizeof(ret));
  if (ret != EXIT_SUCCESS) {
#if !defined(NDEBUG)
    fprintf(stderr, "Failed to create signature\n");
    fflush(stderr);
#endif
    return -1;
  }
  ret = serializeSignature2(&sig, signature, *signature_len);
  if (ret == -1) {
#if !defined(NDEBUG)
    fprintf(stderr, "Failed to serialize signature\n");
    fflush(stderr);
#endif
    return -1;
  }
  *signature_len = ret;

  return 0;
}

int impl_verify_picnic3(const uint8_t* plaintext, const uint8_t* public_key, const uint8_t* msg,
                        size_t msglen, const uint8_t* signature, size_t signature_len) {
  int ret;
  signature2_t sig;

  ret = deserializeSignature2(&sig, signature, signature_len);
  if (ret != EXIT_SUCCESS) {
#if !defined(NDEBUG)
    fprintf(stderr, "Failed to deserialize signature\n");
    fflush(stderr);
#endif
    return -1;
  }

  ret = verify_picnic3(&sig, public_key, plaintext, msg, msglen);
  if (ret != EXIT_SUCCESS) {
    /* Signature is invalid, or verify function failed */
    return -1;
  }

  return 0;
}
