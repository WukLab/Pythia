#ifndef RSEC_HEADER_FILE
#define RSEC_HEADER_FILE

#define _GNU_SOURCE
#include <glib.h>
#include <gmodule.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>

#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "ibsetup.h"
#include "memcached.h"
#include <numa.h>
#include <malloc.h>
#include <limits.h>

#include "rsec_struct.h"
#include "rsec_util.h"

#define RSEC_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define RSEC_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define RSEC_ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define RSEC_ABS(N) ((N < 0) ? (-N) : (N))

#define RSEC_BIT_MASK(__TYPE__, __ONE_COUNT__) \
    ((__TYPE__)(-((__ONE_COUNT__) != 0))) &    \
        (((__TYPE__) - 1) >>                   \
         ((sizeof(__TYPE__) * CHAR_BIT) - (__ONE_COUNT__)))

#define RSEC_64BIT_MASK(param) RSEC_BIT_MASK(unsigned long long, param)
#define RSEC_64BIT_MSB_MASK(input, param) \
    (input - (input &RSEC_64BIT_MASK(64 - param)))
#define RSEC_64BIT_INTERNAL_MASK(left, right) \
    ((RSEC_64BIT_MASK(left)) - (RSEC_64BIT_MASK(right)))

#define RSEC_MB_UNIT (1024 * 1024)

#define RSEC_NS_TO_US(input) (input / 1000)

#define RSEC_GLONG_TO_POINTER(l) ((gpointer)(l))

#define RSEC_SERVER_QP_NUM 0
#define RSEC_HELPER_QP_NUM 0

void dbg_printf(const char *fmt, ...);
void die_printf(const char *fmt, ...);
double diff_ns(struct timespec *, struct timespec *);
double current_ms(struct timespec *start);
int stick_this_thread_to_core(int core_id);
void get_file(char **op, int **key, char *path_string, int test_times);

// priority queue implementation
typedef struct priq_node {
    int data;
    // Lower values indicate higher priority
    double priority;

    struct priq_node *next;

} priq_Node;

priq_Node *priq_newNode(int d, double p);
int priq_peek(priq_Node **head);
double priq_peek_prio(priq_Node **head);
void priq_pop(priq_Node **head);
void priq_push(priq_Node **head, int d, double p);
int priq_isEmpty(priq_Node **head);

void array_swap(int *a, int *b);
void array_randomize(int arr[], int n);

enum RSEC_EXP_MODE_OPTION {
    RSEC_EXP_MODE_GUESS = 1,
    RSEC_EXP_MODE_CACHE = 2,
};
#define RSEC_EXP_MODE RSEC_EXP_MODE_CACHE
#define RSEC_EXP_MODE_CACHE_TARGET 0
static const char *const rsec_experiment_mode_text[] = {
    "------RSEC STRING------", "RSEC_EXP_GUESS",
    "RSEC_EXP_CACHE",          "RSEC_EXP_YCSB"};

#define RSEC_OPERATION_WRITE 1
#define RSEC_OPERATION_READ 2

static const char *const rsec_operation_mode_text[] = {
    "------RSEC STRING------", "RSEC_OPERATION_WRITE", "RSEC_OPERATION_READ"};

#define RSEC_ALLOC_MR_ORIENTED 1
#define RSEC_ALLOC_SPACE_ORIENTED 2
#define RSEC_ALLOC_MODE RSEC_ALLOC_SPACE_ORIENTED
static const char *const rsec_alloc_mode_text[] = {"------RSEC STRING------",
                                                   "RSEC_ALLOC_MR_ORIENTED",
                                                   "RSEC_ALLOC_SPACE_ORIENTED"};

#define RSEC_ATTACK_QP_NUMBER 1024
#define RSEC_ATTACK_QP_STRING_SERVER "attack-server-qp-%d"
#define RSEC_ATTACK_QP_STRING_ATTACKER "attack-attacker-qp-%d"

#define RSEC_NUMA_NODE 0
//#define RSEC_MR_NUMBER (1<<16)
#define RSEC_VALUE_SIZE 1024
#define RSEC_MR_SIZE 4096
//[CAUTION] this MR_SIZE will be round up to fit rsec_entry size in order to
// support oram
#define RSEC_PAGE_SIZE 4096
//#define RSEC_MAX_MR_BLOCK_SIZE (1024*1024*512)
#define RSEC_MAX_MR_BLOCK_SIZE_KB (1024 * 1024 * 40)

#define RSEC_ALLOC_TOTAL_SET_SIZE_KB (1024 * 1024 * 40)
//#define RSEC_ALLOC_TOTAL_SET_SIZE_KB (1024*16)
#define RSEC_MR_NUMBER \
    ((long long int)RSEC_ALLOC_TOTAL_SET_SIZE_KB / (RSEC_MR_SIZE / 1024))
#define RSEC_REAL_BLOCK_SIZE (RSEC_ROUND_UP(RSEC_VALUE_SIZE, RSEC_MR_SIZE))

#define RSEC_EVICT_STRING "%d-%d-evict-ready"
#define RSEC_WARMUP_STRING_1 "%d-%d-1-warmup-ready"
#define RSEC_WARMUP_STRING_2 "%d-%d-2-warmup-ready"
#define RSEC_WARMUP_STRING_3 "%d-%d-3-warmup-ready"
#define RSEC_WARMUP_STRING_4 "%d-%d-4-warmup-ready"
#define RSEC_TERMINATE_STRING "%d-terminate"

//#define RSEC_EVICT_MR_SIZE RSEC_MR_SIZE
#define RSEC_EVICT_MR_SIZE 8
#define RSEC_EVICT_MR_OFFSET 0
#define RSEC_EVICT_MR_NUMBER (1 << 12)
//#define RSEC_EVICT_MR_NUMBER 1
#define RSEC_EVICT_MR_PROCESS_NUMBER ((1 << 10))
#define RSEC_PROBE_STRIDE_DISTANCE (1 << 17)
#define RSEC_PROBE_START_DISTANCE (1 << 25)
//#define RSEC_PROBE_DEFAULT_START_DISTANCE (1<<25)
#define RSEC_PROBE_DEFAULT_START_DISTANCE (1 << 30)
#define RSEC_PROBE_ACCEPT_WRAP_UP 0
#define RSEC_PROBE_SHIFT_SET 0
#define RSEC_MR_UNIFORM_PICK_NUMBER -32768
#define RSEC_MR_MOD_NUMBER 16

#define RSEC_EXTRA_MR 1
#define RSEC_EXTRA_MR_STRING "extra_mr"

#define ACCESS_TEST_MODE 2

//#define RSEC_PROBE_MR_NUMBER (1<<22)
#define RSEC_PROBE_MR_NUMBER (RSEC_MR_NUMBER - (RSEC_PROBE_START_DISTANCE) * 2)
enum RSEC_PROBE_COLLISION_CHECK_MODE_OPTION {
    RSEC_PROBE_COLLISION_CHECK_MODE_MR = 0,
    RSEC_PROBE_COLLISION_CHECK_MODE_PROBE = 1,
    RSEC_PROBE_COLLISION_CHECK_MODE_ALWAYS = 2,
    RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM = 3,
    RSEC_PROBE_COLLISION_CHECK_MODE_ASSOCIATE = 4,
    RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE = 5
};
static const char *const rsec_experiment_evict_mode[] = {
    "RSEC_PROBE_COLLISION_CHECK_MODE_MR",
    "RSEC_PROBE_COLLISION_CHECK_MODE_PROBE",
    "RSEC_PROBE_COLLISION_CHECK_MODE_ALWAYS",
    "RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM",
    "RSEC_PROBE_COLLISION_CHECK_MODE_ASSOCIATE",
    "RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE", };
#define RSEC_PROBE_COLLISION_CHECK_MODE RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM

const static int PROBE_TEST_ARRAY[4] = {
    RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE,
    RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM,
    RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE,
    RSEC_PROBE_COLLISION_CHECK_MODE_ASSOCIATE};

#define RSEC_CACHE_SET_IGNORE_BITS 14
#define RSEC_CACHE_SET_IGNORE_MASK \
    RSEC_64BIT_INTERNAL_MASK(64, RSEC_CACHE_SET_IGNORE_BITS)
#define RSEC_CACHE_SET_NOISE_BITS 0

#define RSEC_CACHE_SET_N_HEIGHT_LEFT 19   // LEFT means this bit is not included
#define RSEC_CACHE_SET_N_HEIGHT_RIGHT 14  // RIGHT means this bit is included
#define RSEC_CACHE_SET_MASK                                 \
    (RSEC_64BIT_INTERNAL_MASK(RSEC_CACHE_SET_N_HEIGHT_LEFT, \
                              RSEC_CACHE_SET_N_HEIGHT_RIGHT))
#define RSEC_CACHE_SET_UNIT_SIZE (1 << RSEC_CACHE_SET_N_HEIGHT_LEFT)
//#define RSEC_CACHE_SET_MASK(input) RSEC_64BIT_MSB_MASK(input,
// RSEC_CACHE_SET_N_HEIGHT)
// N is the height of mapping table
//#define RSEC_CACHE_SLOT_M_WIDTH 6
#define RSEC_CACHE_SLOT_M_WIDTH_LEFT 32
#define RSEC_CACHE_SLOT_M_WIDTH_RIGHT 20
#define RSEC_CACHE_SLOT_MASK                                \
    (RSEC_64BIT_INTERNAL_MASK(RSEC_CACHE_SLOT_M_WIDTH_LEFT, \
                              RSEC_CACHE_SLOT_M_WIDTH_RIGHT))
//#define RSEC_CACHE_SLOT_MASK(input) RSEC_64BIT_MASK(RSEC_CACHE_SLOT_M_LENGTH)
//#define RSEC_CACHE_SLOT_MASK(input) RSEC_64BIT_MSB_MASK(input,
// RSEC_CACHE_SLOT_M_WIDTH)
// M is the width of mapping table (num of slots)

//#define RSEC_EVICT_MR_SIZE RSEC_MR_SIZE

#define RSEC_EVICT_QP_SIZE 128
#define RSEC_EVICT_QP_OFFSET 0
#define RSEC_EVICT_QP_NUMBER RSEC_ATTACK_QP_NUMBER
#define RSEC_EVICT_MODE RSEC_OPERATION_READ

#define RSEC_RELOAD_MR_SIZE RSEC_VALUE_SIZE
#define RSEC_RELOAD_MR_OFFSET 0
#define RSEC_RELOAD_MR_NUMBER 2
#define RSEC_RELOAD_WARMUP_NUMBER 10
#define RSEC_RELOAD_MODE RSEC_OPERATION_READ

#define RSEC_ACCESS_SET_STRING "access-set"
#define RSEC_ACCESS_TEST_RUNNING_TIMES 5000
#define RSEC_ACCESS_TEST_TIME 100
#define RSEC_ACCESS_MR_SIZE RSEC_VALUE_SIZE
#define RSEC_ACCESS_MR_OFFSET RSEC_EVICT_MR_OFFSET
#define RSEC_ACCESS_STRING "%d-%d-access-ready"
#define RSEC_ACCESS_MR_NUMBER 1
#define RSEC_ACCESS_MR_RANGE RSEC_RELOAD_MR_NUMBER

#define RSEC_ACCESS_MODE RSEC_OPERATION_READ
//[CAUTION] this value is fixed to RSEC_OPERATION_READ
#define RSEC_ACCESS_RANGE_DIFFERENCE (1 << 3)

#define RSEC_VERIFY_DEPTH 1
#define RSEC_DEBUG_VERIFY_DEPTH 10
#define RSEC_VERIFY_SHOW_LATENCY_DIFFERENCE 0

#define RSEC_EVICT_BUILD_SET_THRESHOLD 1400
#define RSEC_PROBE_TIME_THRESHOLD 20
#define RSEC_PROBE_TIME_GAP 40
#define RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER 100
#define RSEC_EVICT_BUILD_PROBE

#define RSEC_MEMCACHED_STRING_LENGTH 256

#define RSEC_ESTIMATED_EVICT_REMOTE_LATENCY 2300
//#define RSEC_ESTIMATED_EVICT_REMOTE_LATENCY 4400
#define RSEC_ESTIMATED_EVICT_LOCAL_LATENCY 2400

#define RSEC_ESTIMATED_HIT_REMOTE_LATENCY 2000
//#define RSEC_ESTIMATED_HIT_REMOTE_LATENCY 4000
#define RSEC_ESTIMATED_HIT_LOCAL_LATENCY 1900

#define RSEC_ESTIMATED_EVICT_FETCH_LATENCY 100
#define RSEC_ESTIMATED_EVICT_FETCH_LATENCY_MAX 10000

//#define RSEC_ESTIMATED_REMOTE
#ifdef RSEC_ESTIMATED_REMOTE
#define RSEC_ESTIMATED_EVICT_LATENCY RSEC_ESTIMATED_EVICT_REMOTE_LATENCY
#define RSEC_ESTIMATED_HIT_LATENCY RSEC_ESTIMATED_HIT_REMOTE_LATENCY
#else
#define RSEC_ESTIMATED_EVICT_LATENCY RSEC_ESTIMATED_EVICT_LOCAL_LATENCY
#define RSEC_ESTIMATED_HIT_LATENCY RSEC_ESTIMATED_HIT_LOCAL_LATENCY
#endif

#define RSEC_RELOAD_VPN_FILE "random_vpn.wld"
#define RSEC_RELOAD_VPN_LENGTH 1000

enum RSEC_PROBE_STRIDE_STRATEGY {
    RSEC_PROBE_STRIDE_STRATEGY_NULL = 0,
    RSEC_PROBE_STRIDE_STRATEGY_PYTHIA = 1,
    RSEC_PROBE_STRIDE_STRATEGY_HALF = 2,
    RSEC_PROBE_STRIDE_STRATEGY_NAIVE = 3
};
static const char *const rsec_probe_stride_strategy[] = {
    "RSEC_PROBE_STRIDE_NO_STRATEGY",   "RSEC_PROBE_STRIDE_STRATEGY_PYTHIA",
    "RSEC_PROBE_STRIDE_STRATEGY_HALF", "RSEC_PROBE_STRIDE_STRATEGY_NAIVE", };

#define RSEC_MAX_LATENCY 0xffffffffffff

//#define RSEC_SERVER_RAND_KEY (0xDEADBEEF)
//#define RSEC_CLIENT_RAND_KEY (0xCAFED00F)

//#define RSEC_SERVER_RAND_KEY (0xFEEDC0DE)
//#define RSEC_CLIENT_RAND_KEY (0xBAADF00D)

//#define RSEC_SERVER_RAND_KEY (0x00BAB10C)
//#define RSEC_CLIENT_RAND_KEY (0xB105F00D)

#define RSEC_SERVER_RAND_KEY (time(NULL))
#define RSEC_CLIENT_RAND_KEY (time(NULL))

#define RSEC_SIGNAL_SIZE sizeof(unsigned long)

void *rsec_malloc(long long int size, GArray *allocate_array);
void rsec_free(void *input_ptr);
void rsec_free_all(GArray *allocate_array);
struct ib_mr_attr **rsec_form_sub_mr(struct ib_mr_attr *evict_mr_list,
                                     int length, int *access_order);
struct ib_mr_attr **rsec_form_attack_sub_mr(
    uint32_t target_rkey, struct ib_mr_attr *evict_mr_list, int required_mr_num,
    int *real_process_number, int total_accessible_mr, int stride_distance);
struct ib_mr_attr __attribute__((optimize("O0"))) *
    *rsec_form_attack_sub_mr_new(struct ib_mr_attr *evict_mr_list,
                                 int target_mr_num, int total_accessible_mr,
                                 int collision_check,
                                 int *real_process_mr_number, int shift,
                                 int access_target,
                                 struct return_int *index_set,
                                 int custom_stride_distance, int custom_rkey,
                                 int stride_strategy);
struct ib_mr_attr *rsec_alloc_all_key(struct ib_inf *share_inf, int num_key,
                                      long long int size, int force_mr,
                                      GArray *malloc_array);
priq_Node *rsec_reload_mr(struct ibv_cq *tar_cq, struct ibv_qp *tar_qp,
                          struct ibv_mr *local_mr,
                          struct ib_mr_attr **reload_mr_list, int length,
                          struct ib_mr_attr **evict_mr_list, int *reload_order);
void rsec_access_mr(struct ibv_cq *tar_cq, struct ibv_qp *tar_qp,
                    struct ibv_mr *local_mr, struct ib_mr_attr **access_mr_list,
                    int length);
double diff_ns(struct timespec *start, struct timespec *end);
double sum_diff_ns(struct timespec *start, struct timespec *end, int flag);
int __attribute__((optimize("O0")))
    rsec_get_threshold(struct ibv_cq *server_cq, struct ibv_qp *server_qp,
                       struct ibv_cq *memory_cq, struct ibv_qp *memory_qp,
                       struct ibv_mr *local_mr,
                       struct ib_mr_attr *single_reload_mr,
                       struct ibv_send_wr **input_wr_list, int total_wr_length,
                       double *ret_lat_evict, double *ret_lat_hit, int attacker,
                       int iteration);
struct ibv_send_wr **rsec_form_wr_list(struct ibv_mr *temp_mr,
                                       struct ib_mr_attr **sub_evict_mr_list,
                                       struct ibv_sge *input_sge,
                                       int real_process_mr_number,
                                       uint32_t extra_rkey,
                                       uint64_t extra_offset);

int get_access_target(int running_times, int *key_array);

int get_evict_mode(int running_times);

int get_shift_target(int access_target, int running_times);

int get_stride_distance_target(int running_times);

int get_stride_strategy(int running_times);

int get_num_evict_target(int running_times);

int get_mr_target(int running_times, uint32_t *extra_rkey);
#endif
