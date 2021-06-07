#include "config.h"

#ifdef STM32F4
#include "keccak/KeccakP-1600-inplace-32bi-armv7m-le-gcc.S.i"
#ifndef KECCAK_MASK_NONE
#include "keccak/KeccakP-1600-inplace-32bi-armv7m-le-gcc-mpc.S.i"
#endif
#endif
