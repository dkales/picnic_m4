/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */
#ifndef MASKING_H
#define MASKING_H

#include <stdint.h>
#include "picnic_params.h"

/* This file contains some constants required for the masked signing implementation */

/* Set this to one to have the implementation print a verbose trace of intermediate values 
 * Useful for comparing the the same output from the unmasked implementation.
 * Best if the signing code exit()s after one MPC instance, and use the kats program
 * so that signing is deterministic with a fixed keypair and message. 
 */
#define PICNIC_DEBUG_TRACE 0

/* The number of shares to use for the masked implementation */
#define MASKING_T 2

/* Toggle whether to use the randomized AND gadget (SNI-secure) or non-randomized (more heuristic security) */
#define MAKSING_RANDOMIZED_AND 1

/* Basic data type for t-sharings.  The length is fixed to the LowMC blocksize/keysize */
typedef struct masked_uint8_t {
  uint8_t shares[MASKING_T][PICNIC_INPUT_SIZE];
} masked_uint8_t;

typedef struct masked_aux_t {
  uint8_t shares[MASKING_T][PICNIC_AUX_SIZE];
} masked_aux_t;

/* Masked tape for one party */
typedef struct masked_tape_t {
  uint8_t shares[MASKING_T][PICNIC_TAPE_SIZE];
} masked_tape_t;

/* Masked msgs broadcast by one party */
typedef struct masked_view_t {
  uint8_t shares[MASKING_T][PICNIC_VIEW_SIZE];
} masked_view_t;

#endif /* MASKING_H */