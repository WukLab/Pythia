#define _GNU_SOURCE
#include <sched.h>
#include "memcached.h"
#include "server.h"
#define DBG_STRING "server"
#include <sys/unistd.h>
#define RSEC_ROLE SERVER
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "rsec.h"
#define NUM_CORES 22

/**
 * server.c: this code is for server
 */
struct configuration_params *param_arr;
struct ib_inf *node_share_inf;
pthread_t *thread_arr;
pthread_barrier_t local_barrier;
pthread_barrier_t cycle_barrier;

/**
 * run_server -
 * 1. initialize server function
 * 2. issue requests to setup connections
 * 3. setup all pre-allocated memory entries
 * @arg: input parameter
 */
void *run_server(void *arg) {
    int i;
    struct configuration_params *input_arg = arg;
    int machine_id = input_arg->machine_id;
    int num_threads = input_arg->total_threads;
    int num_servers = input_arg->num_servers;
    int num_clients = input_arg->num_clients;
    int base_port_index = input_arg->base_port_index;
    int ret;
    param_arr = malloc(num_threads * sizeof(struct configuration_params));
    thread_arr = malloc(num_threads * sizeof(pthread_t));
    // initialize barrier
    ret = pthread_barrier_init(&local_barrier, NULL, input_arg->total_threads);
    if (ret)
        die_printf("[%s] fail to create barrier %d thread %d\n", __func__, ret,
                   input_arg->total_threads);
    // initialize thread
    for (i = num_threads - 1; i >= 0; i--) {
        param_arr[i].global_thread_id = (machine_id << RSEC_ID_SHIFT) + i;
        param_arr[i].local_thread_id = i;
        param_arr[i].base_port_index = base_port_index;
        param_arr[i].num_servers = num_servers;
        param_arr[i].num_clients = num_clients;
        param_arr[i].machine_id = machine_id;
        param_arr[i].total_threads = num_threads;
        param_arr[i].device_id = input_arg->device_id;
        param_arr[i].num_loopback = input_arg->num_loopback;
        param_arr[i].num_attack_qps = RSEC_ATTACK_QP_NUMBER;
        if (i != 0)
            pthread_create(&thread_arr[i], NULL, main_server, &param_arr[i]);
        else
            main_server(&param_arr[0]);
    }
    return NULL;
}

/**
 * main_server - finish all InfiniBand/RDMA connection setup, regular server
 * and helper(only used by Crail attack) are separated from this function
 * @arg: input parameter
 */
void *main_server(void *arg) {
    struct configuration_params *input_arg = arg;
    struct ib_local_inf *node_private_inf;

    node_share_inf = ib_complete_setup(input_arg, RSEC_ROLE, DBG_STRING);
    assert(node_share_inf != NULL);
    node_private_inf = ib_local_setup(input_arg, node_share_inf);
    printf("finish all server initialization\n");
    if (input_arg->machine_id == 0)
        server_code(node_share_inf, node_private_inf, input_arg);
    else
        helper_code(node_share_inf, node_private_inf, input_arg);
    printf("ready to press ctrl+c to finish experiment\n");
    while (1)
        ;
}

/**
 * helper_code - major code helper is running in Pythia
 * 1. register all memory space
 * 2. share all memory space to attacker
 * @global_inf: RDMA context
 * @local_inf: RDMA context-subset
 * @input_arg: input parameter
 */
void helper_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg) {
    GArray *rsec_malloc_array;
    rsec_malloc_array = g_array_new(FALSE, FALSE, sizeof(guint64));
    struct ib_mr_attr *evict_key_list =
        rsec_alloc_all_key(node_share_inf, RSEC_EVICT_MR_NUMBER, RSEC_MR_SIZE,
                           1, rsec_malloc_array);
    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, "evict-mr-key");
        memcached_publish(mem_mr_name, evict_key_list,
                          sizeof(struct ib_mr_attr) * RSEC_EVICT_MR_NUMBER);
    }

    RSEC_PRINT("this node is running helper code\n");
    RSEC_PRINT("this is for RSEC_HELPER\n");
    {
        char *memcached_string = malloc(RSEC_MEMCACHED_STRING_LENGTH);
        int per_machine;

        memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
        sprintf(memcached_string, RSEC_TERMINATE_STRING, input_arg->machine_id);
        memcached_publish(memcached_string, &input_arg->machine_id,
                          sizeof(int));

        for (per_machine = 0; per_machine < global_inf->global_machines;
             per_machine++) {
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_TERMINATE_STRING, per_machine);
            memcached_get_published_size(memcached_string, sizeof(int));
        }
        free(memcached_string);
        rsec_free_all(rsec_malloc_array);
        RSEC_PRINT("helper finish experiment\n");
    }
    return;
}

/**
 * server_code - major code server is running in Pythia
 * 1. register all memory space
 * 2. share all memory space to client and attacker
 * @global_inf: RDMA context
 * @local_inf: RDMA context-subset
 * @input_arg: input parameter
 */
void server_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg) {
    int i;
    GArray *rsec_malloc_array;
    rsec_malloc_array = g_array_new(FALSE, FALSE, sizeof(guint64));
    // struct ib_mr_attr *rkey_list = rsec_alloc_all_key(node_share_inf,
    // RSEC_MR_NUMBER, RSEC_ROUND_UP(sizeof(rsec_entry), RSEC_MR_SIZE), 0,
    // rsec_malloc_array);
    // struct ib_mr_attr *rkey_list = rsec_alloc_all_key(node_share_inf,
    // RSEC_MR_NUMBER, RSEC_MR_SIZE, 0, rsec_malloc_array);
    struct ib_mr_attr *rkey_list =
        rsec_alloc_all_key(node_share_inf, RSEC_MR_NUMBER, RSEC_REAL_BLOCK_SIZE,
                           0, rsec_malloc_array);
    {
        uint32_t *extra_rkey = malloc(sizeof(uint32_t) * RSEC_EXTRA_MR);
        for (i = 0; i < RSEC_EXTRA_MR; i++) {
            struct ibv_mr *tmp_mr;
            tmp_mr = ibv_reg_mr(
                node_share_inf->pd, (void *)rkey_list[0].addr,
                RSEC_ROUND_UP(RSEC_VALUE_SIZE, RSEC_MR_SIZE) * RSEC_MR_NUMBER,
                IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                    IBV_ACCESS_REMOTE_READ);
            extra_rkey[i] = tmp_mr->rkey;
            if (i % 10 == 0)
                RSEC_PRINT("allocate %d/%d MR\n", i, RSEC_EXTRA_MR);
        }
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, RSEC_EXTRA_MR_STRING);
        memcached_publish(mem_mr_name, extra_rkey,
                          sizeof(uint32_t) * RSEC_EXTRA_MR);
    }
    struct ib_mr_attr *evict_key_list;
    // struct ib_mr_attr *probe_key_list;
    if (RSEC_HELPER_QP_NUM == 0) {
        RSEC_PRINT("alloc MR\n");
        evict_key_list =
            rsec_alloc_all_key(node_share_inf, RSEC_EVICT_MR_NUMBER,
                               RSEC_MR_SIZE, 1, rsec_malloc_array);
        RSEC_PRINT("finish alloc MR\n");
    }
    int *access_set = malloc(sizeof(int) * RSEC_MR_NUMBER);
    char access_set_name[RSEC_MAX_QP_NAME];

    srand(RSEC_SERVER_RAND_KEY);
    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, "mr-key");
        // memcached_publish(mem_mr_name, rkey_list, sizeof(struct ib_mr_attr) *
        // RSEC_MR_NUMBER);
        memcached_publish(mem_mr_name, &rkey_list[0],
                          sizeof(struct ib_mr_attr));
    }

    if (RSEC_HELPER_QP_NUM == 0) {
        {
            char mem_mr_name[RSEC_MAX_QP_NAME];
            sprintf(mem_mr_name, "evict-mr-key");
            memcached_publish(mem_mr_name, evict_key_list,
                              sizeof(struct ib_mr_attr) * RSEC_EVICT_MR_NUMBER);
        }
    }

    for (i = 0; i < RSEC_ACCESS_MR_RANGE; i++) {
        access_set[i] = i * RSEC_ACCESS_RANGE_DIFFERENCE;
    }

    sprintf(access_set_name, RSEC_ACCESS_SET_STRING);
    memcached_publish(access_set_name, access_set,
                      sizeof(int) * RSEC_ACCESS_MR_RANGE);

    {
        char *memcached_string = malloc(RSEC_MEMCACHED_STRING_LENGTH);
        int per_machine;

        memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
        sprintf(memcached_string, RSEC_TERMINATE_STRING, input_arg->machine_id);
        memcached_publish(memcached_string, &input_arg->machine_id,
                          sizeof(int));

        for (per_machine = 0; per_machine < global_inf->global_machines;
             per_machine++) {
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_TERMINATE_STRING, per_machine);
            memcached_get_published_size(memcached_string, sizeof(int));
        }
        free(memcached_string);
        rsec_free_all(rsec_malloc_array);
        RSEC_PRINT("server finish experiment\n");
    }
    return;
}
