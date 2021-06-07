/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef KDF_SHAKE_H
#define KDF_SHAKE_H

#include <stdint.h>
#include <alloca.h>

#include "macros.h"
#include "endian_compat.h"
#include "randomness.h"

#if defined(WITH_SHAKE_S390_CPACF)
/* use the KIMD/KLMD instructions from CPACF for SHAKE support on S390 */
#include "s390_cpacf.h"
#else
#if !defined(SUPERCOP)
/* use SHAKE implementation in sha3/ */
#include "KeccakHash.h"
#include "KeccakMPCHash.h"
#else
/* use SUPERCOP implementation */
#include <libkeccak.a.headers/KeccakHash.h>
#endif

#ifdef PROFILE_HASHING
#include "hal.h"
extern unsigned long long hash_cycles;
#endif

#ifdef KECCAK_MASK_ALL    /* When KECCAK_MASK_ALL is set, ALL calls to SHA-3 are masked. */
typedef KeccakMPC_HashInstance hash_context ATTR_ALIGNED(32);
typedef KeccakMPC_HashInstance masked_hash_context ATTR_ALIGNED(32);
#else                    /* Otherwise, we only mask those calls that use masked_hash_context */
typedef Keccak_HashInstance hash_context ATTR_ALIGNED(32);
#ifdef KECCAK_MASK_NONE
typedef Keccak_HashInstance masked_hash_context ATTR_ALIGNED(32);
#else
typedef KeccakMPC_HashInstance masked_hash_context ATTR_ALIGNED(32);
#endif
#endif

#ifdef KECCAK_MASK_NONE

static inline void array_xor(uint8_t* a, const uint8_t* b, const uint8_t* c, size_t len ) {
  size_t i;
  for( i=0; i< len; i++) {
    a[i] = b[i] ^ c[i];
  }
}

static inline void masked_hash_init(masked_hash_context *ctx, size_t digest_size, size_t shareCount) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  (void)shareCount;
  if( digest_size == 32) {
    Keccak_HashInitialize_SHAKE128(ctx);
  } else {
    Keccak_HashInitialize_SHAKE256(ctx);
  }
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_update(masked_hash_context* ctx, const uint8_t** data, size_t byteLen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  uint8_t *buffer = alloca(byteLen);
  array_xor(buffer, data[0], data[1], byteLen);
  Keccak_HashUpdate(ctx, buffer, byteLen * 8);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_final(masked_hash_context* ctx) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  Keccak_HashFinal(ctx, NULL);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_squeeze(masked_hash_context* ctx, uint8_t** digestShares, size_t byteLen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  uint8_t *buffer = alloca(byteLen);
  Keccak_HashSqueeze(ctx, buffer, byteLen * 8);
  memcpy(digestShares[0], buffer, byteLen);
  memset(digestShares[1], 0, byteLen);
#ifdef KECCAK_SNI_SECURE
  rand_mask(buffer, byteLen);
  array_xor(digestsShares[0], digestsShares[0], buffer);
  array_xor(digestsShares[1], digestsShares[1], buffer);
#endif
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_update_uint16_le(masked_hash_context* ctx, uint16_t ** shares) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  Keccak_HashUpdate(ctx, (const uint8_t*)shares[0], 16);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

#else /* KECCAK_MASK_NONE */

static inline void masked_hash_init(masked_hash_context *ctx, size_t digest_size, size_t shareCount) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  if (shareCount != 2) {
    return;
  }
  if( digest_size == 32) {
    KeccakMPC_HashInitialize_2SHARE_SHAKE128(ctx);
  } else {
    KeccakMPC_HashInitialize_2SHARE_SHAKE256(ctx);
  }
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_update(masked_hash_context* ctx, const uint8_t** data, size_t byteLen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  KeccakMPC_HashUpdate(ctx, (uint8_t**)data, byteLen * 8);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_final(masked_hash_context* ctx) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  KeccakMPC_HashFinal(ctx, NULL);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_squeeze(masked_hash_context* ctx, uint8_t** digestShares, size_t byteLen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  KeccakMPC_HashSqueeze(ctx, digestShares, byteLen * 8);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void masked_hash_update_uint16_le(masked_hash_context* ctx, uint16_t ** shares) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  KeccakMPC_HashUpdate(ctx, (BitSequence**)shares, 16);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

#endif /* KECCAK_MASK_NONE */

static inline void masked_hash_init_prefix(masked_hash_context* ctx, size_t digest_size, const uint8_t prefix, size_t shareCount) {
  masked_hash_init(ctx, digest_size, shareCount);
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  uint8_t **shares = alloca(shareCount * sizeof(uint8_t**));
  uint8_t * slab = alloca(shareCount);
  shares[0] = slab;
  shares[0][0] = prefix;
  for(size_t i = 1; i < shareCount; ++i) {
    shares[i] = slab + i;
    shares[i][0] = 0;
  }
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
  masked_hash_update(ctx, (const uint8_t **)shares, 1);
}

#ifdef KECCAK_MASK_ALL

static inline void array_xor(uint8_t* a, const uint8_t* b, const uint8_t* c, size_t len ) {
  size_t i;
  for( i=0; i< len; i++) {
    a[i] = b[i] ^ c[i];
  }
}

/**
 * Initialize hash context based on the digest size used by Picnic. If the size is 32 bytes,
 * SHAKE128 is used, otherwise SHAKE256 is used.
 */
static inline void hash_init(hash_context* ctx, size_t digest_size) {
  masked_hash_init(ctx,digest_size, 2);
}

static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  const int shareCount = 2;
  uint8_t ** shares = alloca(shareCount * sizeof(uint8_t*));
  for(int i = 0; i < shareCount; i++) {
    shares[i] = alloca(size);
  }
  memcpy(shares[shareCount-1],data,size);

  //set pointers of "outer" array and fill last share with xor
  for(int i = 0; i < shareCount-1; i++) {
    rand_mask(shares[i], size);
    array_xor(shares[shareCount-1], shares[shareCount-1], shares[i], size);
  }
  #ifdef PROFILE_HASHING
    uint64_t t1 = hal_get_time();
    hash_cycles += (t1-t0);
  #endif

  masked_hash_update(ctx, (const uint8_t**)shares, size);
}

static inline void hash_final(hash_context* ctx) {
  masked_hash_final(ctx);
}

static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  const int shareCount = 2;
  uint8_t ** shares = alloca(ctx->shareCount * sizeof(uint8_t*));

  for(int i = 0; i < shareCount; i++) {
	shares[i] = alloca(buflen);
  }
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif

  masked_hash_squeeze(ctx, shares, buflen);

#ifdef PROFILE_HASHING
  t0 = hal_get_time();
#endif
  memset(buffer,0,buflen);
  for(int i = 0; i < shareCount; i++) {
    array_xor(buffer, buffer, shares[i], buflen);
  }
#ifdef PROFILE_HASHING
  t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void hash_update_uint16_le(hash_context* ctx, uint16_t data) {
  uint16_t zero = 0;
  uint16_t *shares[2] = {&data, &zero};
  masked_hash_update_uint16_le(ctx, (uint16_t**) shares);
}

static inline void hash_init_prefix(hash_context* ctx, size_t digest_size, const uint8_t prefix) {
  masked_hash_init_prefix(ctx, digest_size, prefix, 2);
}

#else /* !KECCAK_MASK_ALL */

/**
 * Initialize hash context based on the digest size used by Picnic. If the size is 32 bytes,
 * SHAKE128 is used, otherwise SHAKE256 is used.
 */
static inline void hash_init(hash_context* ctx, size_t digest_size) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  if (digest_size == 32) {
    Keccak_HashInitialize_SHAKE128(ctx);
  } else {
    Keccak_HashInitialize_SHAKE256(ctx);
  }
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  Keccak_HashUpdate(ctx, data, size << 3);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void hash_final(hash_context* ctx) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  Keccak_HashFinal(ctx, NULL);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {
#ifdef PROFILE_HASHING
  uint64_t t0 = hal_get_time();
#endif
  Keccak_HashSqueeze(ctx, buffer, buflen << 3);
#ifdef PROFILE_HASHING
  uint64_t t1 = hal_get_time();
  hash_cycles += (t1-t0);
#endif
}

static inline void hash_update_uint16_le(hash_context* ctx, uint16_t data) {
  const uint16_t data_le = htole16(data);
  hash_update(ctx, (const uint8_t*)&data_le, sizeof(data_le));
}

static inline void hash_init_prefix(hash_context* ctx, size_t digest_size, const uint8_t prefix) {
  hash_init(ctx, digest_size);
  hash_update(ctx, &prefix, sizeof(prefix));
}

#endif

typedef hash_context kdf_shake_t;
typedef masked_hash_context masked_kdf_shake_t;

#define kdf_shake_init(ctx, digest_size) hash_init((ctx), (digest_size))
#define kdf_shake_init_prefix(ctx, digest_size, prefix)                                            \
  hash_init_prefix((ctx), (digest_size), (prefix))
#define kdf_shake_update_key(ctx, key, keylen) hash_update((ctx), (key), (keylen))
#define kdf_shake_update_key_uint16_le(ctx, key) hash_update_uint16_le((ctx), (key))
#define kdf_shake_finalize_key(ctx) hash_final((ctx))
#define kdf_shake_get_randomness(ctx, dst, count) hash_squeeze((ctx), (dst), (count))
#define kdf_shake_clear(ctx)

#endif


#endif /* KDF_SHAKE_H */
