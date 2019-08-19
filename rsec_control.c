#include "rsec.h"

/**
 * rsec_control.c - this code controls the configuration of attacker
 */

/**
 * get_access_target - get target test/attack entry
 */
int get_access_target(int running_times, int *key_array) {

    if (key_array) return key_array[running_times % RSEC_RELOAD_VPN_LENGTH];
    // DONE DELETE ABOVE LINES
    return (running_times % 4096) * 8;
}

/**
 * get_shift_target - manually shift access offset
 */
int get_shift_target(int access_target, int running_times) {
    return -1;  // pythia
}

/**
 * get_stride_strategy - get different attack ways
 */
int get_stride_strategy(int running_times) {
    return RSEC_PROBE_STRIDE_STRATEGY_PYTHIA;  // pythia
}

/**
 * get_stride_distance_target - manually setups VPN distance between each
 * request
 */
int get_stride_distance_target(int running_times) {
    return -1;  // pythia
}

/**
 * get_num_evict_target - manually setups evict size
 */
int get_num_evict_target(int running_times) {
    // Figure 7 experiment
    int subcycle = running_times % 5000;
    int lengthcycle = subcycle / 1000;
    return (1 << (6 + lengthcycle));
}

/**
 * get_mr_target - manually setups mr evict+reload target
 */
int get_mr_target(int running_times, uint32_t *extra_rkey) { return 0; }

/**
 * get_evict_mode - different evict mode - mr or pte
 */
int get_evict_mode(running_times) {
    return RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE;  // pythia
}
