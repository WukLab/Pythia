
#include "rsec_base.h"
#include <stdio.h>
#include <getopt.h>
#include "server.h"
#include "client.h"

/**
 * init.c: this code initlizes the whole program
 * 1. take input parameter
 * 2. setup connection
 * 3. setup role (server/client/attacker)
 * Part of the code borrows the ideas from libhrd -
 * https://github.com/efficient/rdma_bench/tree/master/libhrd
 */

/**
 * main - entry point of the whole program
 */
int main(int argc, char *argv[]) {
    int i, c;
    int is_master = -1;
    int num_threads = 1;
    int is_client = -1, machine_id = -1, is_server = -1;
    int base_port_index = -1;
    int num_clients = -1, num_servers = -1;
    int device_id = 0;
    int num_loopback = -1;
    int interaction_mode = 0;
    struct configuration_params *param_arr;
    pthread_t *thread_arr;

    static struct option opts[] = {
        {.name = "master", .has_arg = 1, .val = 'h'},
        {.name = "base-port-index", .has_arg = 1, .val = 'b'},
        {.name = "num-clients", .has_arg = 1, .val = 'c'},
        {.name = "num-servers", .has_arg = 1, .val = 's'},
        {.name = "is-client", .has_arg = 1, .val = 'C'},
        {.name = "is-server", .has_arg = 1, .val = 'S'},
        {.name = "machine-id", .has_arg = 1, .val = 'I'},
        {.name = "device-id", .has_arg = 1, .val = 'd'},
        {.name = "num-loopbackset", .has_arg = 1, .val = 'L'},
        {.name = "interaction", .has_arg = 1, .val = 'M'},
        {0}};

    /* Parse and check arguments */
    while (1) {
        c = getopt_long(argc, argv, "h:b:c:m:s:C:S:I:d:L:M:", opts, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'h':
                is_master = atoi(optarg);
                assert(is_master == 1);
                break;
            case 'b':
                base_port_index = atoi(optarg);
                break;
            case 'c':
                num_clients = atoi(optarg);
                break;
            case 's':
                num_servers = atoi(optarg);
                break;
            case 'C':
                is_client = atoi(optarg);
                break;
            case 'S':
                is_server = atoi(optarg);
                break;
            case 'I':
                machine_id = atoi(optarg);
                break;
            case 'd':
                device_id = atoi(optarg);
                break;
            case 'L':
                num_loopback = atoi(optarg);
                break;
            case 'M':
                interaction_mode = atoi(optarg);
                break;
            default:
                printf("Invalid argument %d\n", c);
                assert(0);
        }
    }
    /* Common checks for all (master, workers, clients */
    assert(base_port_index >= 0 && base_port_index <= 8);
    if (interaction_mode) RSEC_PRINT("[INTERACTION MODE]\n");
    /* Common sanity checks for worker process and per-machine client process */
    assert((is_client + is_server) == 0);
    assert((num_loopback) >= 0);
    if (RSEC_PAGE_SIZE > RSEC_MR_SIZE)
        assert(RSEC_PAGE_SIZE % RSEC_MR_SIZE == 0);
    else
        assert(RSEC_MR_SIZE % RSEC_PAGE_SIZE == 0);

    if (RSEC_EXP_MODE == RSEC_EXP_MODE_CACHE) {
        assert(RSEC_RELOAD_MR_NUMBER == 2);
        assert(RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER >= 100);
        assert(RSEC_CACHE_SET_N_HEIGHT_LEFT - RSEC_CACHE_SET_N_HEIGHT_RIGHT >=
               0);
        assert(RSEC_CACHE_SLOT_M_WIDTH_LEFT - RSEC_CACHE_SLOT_M_WIDTH_RIGHT >=
               0);
        assert(RSEC_CACHE_SET_IGNORE_BITS == RSEC_CACHE_SET_N_HEIGHT_RIGHT);
        RSEC_PRINT("SET_UNIT_SIZE: %d:%d %x\tSET_MASK:%llx\n",
                   RSEC_CACHE_SET_N_HEIGHT_LEFT, RSEC_CACHE_SET_UNIT_SIZE,
                   RSEC_CACHE_SET_UNIT_SIZE, RSEC_CACHE_SET_MASK);
    }
    RSEC_PRINT("EXPERIMENT_MODE: %s\n",
               rsec_experiment_mode_text[RSEC_EXP_MODE]);

    assert(RSEC_RELOAD_MR_NUMBER <= RSEC_CQ_DEPTH);
    assert(RSEC_ACCESS_MR_NUMBER <= RSEC_CQ_DEPTH);
    assert(RSEC_EVICT_QP_NUMBER <= RSEC_ATTACK_QP_NUMBER);
    assert(RSEC_DATA_SIZE % RSEC_AES_BLOCK_SIZE == 0);
    if (is_client == 1) {
        assert(num_clients >= 1);
        assert(num_servers >= 1);

        assert(num_threads >= 1);
        assert(machine_id >= 0);
    } else {
        assert(num_clients >= 1);
        assert(num_servers >= 1);
        assert(machine_id >= 0);
    }
    RSEC_PRINT("total MR/alloc_mode:%lld/%s\n", RSEC_MR_NUMBER,
               rsec_alloc_mode_text[RSEC_ALLOC_MODE]);
    RSEC_PRINT("evict MR/process MR/mode:%d/%d/%s\n", RSEC_EVICT_MR_NUMBER,
               RSEC_EVICT_MR_PROCESS_NUMBER,
               rsec_operation_mode_text[RSEC_EVICT_MODE]);
    RSEC_PRINT("access MR/test times/mode:%d/%d/%s\n", RSEC_ACCESS_MR_RANGE,
               RSEC_ACCESS_TEST_TIME,
               rsec_operation_mode_text[RSEC_ACCESS_MODE]);
    assert(RSEC_ACCESS_MODE == RSEC_OPERATION_READ);
    /* Launch a single server thread or multiple client threads */
    // printf("main: Using %d %d threads\n", num_threads, machine_id);
    param_arr = malloc(num_threads * sizeof(struct configuration_params));
    thread_arr = malloc(num_threads * sizeof(pthread_t));
    assert(thread_arr);
    {
        param_arr[0].base_port_index = base_port_index;
        param_arr[0].num_servers = num_servers;
        param_arr[0].num_clients = num_clients;
        param_arr[0].machine_id = machine_id;
        param_arr[0].total_threads = num_threads;
        param_arr[0].device_id = device_id;
        param_arr[0].num_loopback = num_loopback;
        param_arr[0].interaction_mode = interaction_mode;

        if (is_client >= 0) run_client(&param_arr[0]);
        if (is_server >= 0) run_server(&param_arr[0]);
    }
    while (1)
        ;
    for (i = 0; i < num_threads; i++) {
        pthread_join(thread_arr[i], NULL);
    }

    return 0;
}
