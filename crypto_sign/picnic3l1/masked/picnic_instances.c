/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "picnic_instances.h"

#define NULL_FNS {NULL, NULL, NULL}
#define NULL_PARAMS                                                                                   \
    {{0, 0, 0, 0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, PARAMETER_SET_INVALID, NULL_FNS}

/* The indices of this struct are in sync with picnic.h */
static picnic_instance_t instances[PARAMETER_SET_MAX_INDEX] = {
    NULL_PARAMS,     // index 0
    /* ZKB++ with partial LowMC instances (Pinic-FS and -UR) */
    NULL_PARAMS,     // index 1
    NULL_PARAMS,
    NULL_PARAMS,
    NULL_PARAMS,
    NULL_PARAMS,
    NULL_PARAMS,     // index 6
    /* KKW with full LowMC instances (Picnic3) */
    {{43, 129, 4, 129}, 32, 16, 250, 36, 16, 17, 17, 65, 129, 55, 0, 0,
     PICNIC_SIGNATURE_SIZE_Picnic3_L1, Picnic3_L1, NULL_FNS},
    NULL_PARAMS,    // index 8
    NULL_PARAMS,    // index 9
    /* ZKB++ with full LowMC instances (Pincic-full) */
    NULL_PARAMS,    // index 10
    NULL_PARAMS,    // index 11
    NULL_PARAMS,    // index 12
};
static bool instance_initialized[PARAMETER_SET_MAX_INDEX];

static bool create_instance(picnic_instance_t* pp) {
  if (!pp->lowmc.m || !pp->lowmc.n || !pp->lowmc.r || !pp->lowmc.k) {
    return false;
  }

  if (pp->params == Picnic_L1_UR || pp->params == Picnic_L3_UR || pp->params == Picnic_L5_UR) {
    return false;
  }

  pp->impls.lowmc                 = &lowmc_uint64_lowmc_129_129_4;
  pp->impls.lowmc_aux             = &lowmc_compute_aux_uint64_lowmc_129_129_4;
  pp->impls.lowmc_simulate_online = &lowmc_simulate_online_uint64_129_43;

  return true;
}

const picnic_instance_t* picnic_instance_get(picnic_params_t param) {
  if (param <= PARAMETER_SET_INVALID || param >= PARAMETER_SET_MAX_INDEX) {
    return NULL;
  }

  if (!instance_initialized[param]) {
    if (!create_instance(&instances[param])) {
      return NULL;
    }
    instance_initialized[param] = true;
  }

  return &instances[param];
}
