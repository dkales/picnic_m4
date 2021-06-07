#include "config.h"

#ifndef KECCAK_MASK_NONE

#ifdef STM32F4
#include "keccak/KeccakP-1600-inplace-32bi-armv7m-le-gcc-mpc.c.i"
#else
#include "keccak/KeccakP-1600-ref-mpc.c.i"
#endif

#endif
