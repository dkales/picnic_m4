/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef RANDOMNESS_H
#define RANDOMNESS_H

#include <stddef.h>
#include <stdint.h>

int rand_bytes(uint8_t* dst, size_t len);
int rand_bits(uint8_t* dst, size_t num_bits);

#if defined(STM32F4) || defined(MUPQ_NAMESPACE)

/* If we are building under pqm4 for either host or board, use external PRNG. */
#define HAVE_RANDOMBYTES

/* Also define another RNG for mask generation. */
int rand_mask(uint8_t* dst, size_t len);

#else

#define rand_mask rand_bytes

#endif

#endif /* RANDOMNESS_H */
