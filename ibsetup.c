#include "ibsetup.h"
#include "infiniband/verbs.h"
#include "memcached.h"

/**
 * ibsetup.c: this code sets RDMA connection.
 * Part of the code borrows the ideas from libhrd -
 * https://github.com/efficient/rdma_bench/tree/master/libhrd
 */

/**
 * ib_malloc - do memory allocation - could be malloc, memalign, or other malloc
 * library
 * @length: allocation size
 */
void *ib_malloc(size_t length) {
    // void *ret = malloc(length);
    void *ret = memalign(_SC_PAGESIZE, length);
    assert(ret != 0);
    return ret;
}

/**
 * ib_post_recv_ud_qp - setup ud queue pair
 */
int ib_post_recv_ud_qp(struct ib_inf *inf, int udqp_index, int post_recv_base,
                       int post_recv_num) {
    int i, count = 0;
    struct ibv_recv_wr input_wr, *bad_wr;
    struct ibv_sge sge[2];
    int ret;
    if (post_recv_num + post_recv_base > RSEC_CQ_DEPTH) {
        dbg_printf("[%s] post too big nums as %d (%d)\n", __func__,
                   post_recv_num + post_recv_base, RSEC_CQ_DEPTH);
        return -1;
    }
    assert(post_recv_num > 0 && post_recv_base >= 0);
    for (i = post_recv_base; i < post_recv_num + post_recv_base; i++) {
        sge[0].addr = (uintptr_t)inf->dgram_buf_mr[udqp_index][i]->addr;
        sge[0].length = inf->dgram_buf_mr[udqp_index][i]->length;
        sge[0].lkey = inf->dgram_buf_mr[udqp_index][i]->lkey;
        // if(i==0)
        //      dbg_printf("[%s] %lx %lx %lx\n", __func__, sge[0].addr, (long
        // unsigned int)sge[0].length, (long unsigned int)sge[0].lkey);
        input_wr.next = NULL;
        input_wr.sg_list = sge;
        input_wr.wr_id =
            ((uint64_t)i << RSEC_UD_POST_RECV_ID_SHIFT) + (uint64_t)sge[0].addr;
        input_wr.num_sge = 1;
        ret = ibv_post_recv(inf->dgram_qp[udqp_index], &input_wr, &bad_wr);
        if (ret) {
            dbg_printf("[%s] QP %d index %d fail to post_recv. ret %d\n",
                       __func__, udqp_index, i, ret);
        } else
            count++;
    }
    return count;
}

/**
 * ib_get_device - get ib device
 */
struct ibv_device *ib_get_device(struct ib_inf *inf, int port) {
    struct ibv_device **dev_list;
    struct ibv_context *ctx;
    struct ibv_device_attr device_attr;
    struct ibv_port_attr port_attr;
    int i;
    int num_devices;
    dev_list = ibv_get_device_list(&num_devices);
    if (num_devices == 0)  // assuming we only have one device now, need to
                           // modify this part later
        die_printf("%s: num_devices==0\n", __func__);
    if (num_devices <= inf->device_id)
        die_printf("%s: device_id:%d overflow available num_devices:%d\n",
                   __func__, inf->device_id, num_devices);
    i = inf->device_id;
    {
        ctx = ibv_open_device(dev_list[i]);
        if (ibv_query_device(ctx, &device_attr))
            die_printf("%s: failed to query device %d\n", __func__, i);

        RSEC_PRINT("running on %s\n", ibv_get_device_name(dev_list[i]));
        if (device_attr.phys_port_cnt < port)
            die_printf("%s: port not enough %d:%d\n", __func__, port,
                       device_attr.phys_port_cnt);
        if (ibv_query_port(ctx, port, &port_attr))
            die_printf("%s: can't query port %d\n", __func__, port);
        inf->device_id = i;
        inf->dev_port_id = port;
        return dev_list[i];
    }
    return NULL;
}

/**
 * ib_get_gid - setup RDMA gid
 */
union ibv_gid ib_get_gid(struct ibv_context *context, int port_index) {
    union ibv_gid ret_gid;
    int ret;
    ret = ibv_query_gid(context, port_index, RSEC_SGID_INDEX, &ret_gid);
    if (ret) fprintf(stderr, "get GID fail\n");

    fprintf(stderr, "GID: Interface id = %lld subnet prefix = %lld\n",
            (long long)ret_gid.global.interface_id,
            (long long)ret_gid.global.subnet_prefix);

    return ret_gid;
}

/**
 * ib_get_local_lid - get RDMA lid
 */
uint16_t ib_get_local_lid(struct ibv_context *ctx, int dev_port_id) {
    assert(ctx != NULL && dev_port_id >= 1);

    struct ibv_port_attr attr;
    if (ibv_query_port(ctx, dev_port_id, &attr)) {
        die_printf("ibv_query_port on port %d of device %s failed! Exiting.\n",
                   dev_port_id, ibv_get_device_name(ctx->device));
        assert(0);
    }

    return attr.lid;
}

/**
 * ib_create_rcqps - setup RDMA RC qps
 */
void ib_create_rcqps(struct ib_inf *inf, int role_int) {
    int i;
    assert(inf->conn_qp != NULL && inf->conn_cq != NULL && inf->pd != NULL &&
           inf->ctx != NULL);
    assert(inf->num_local_rcqps >= 1 && inf->dev_port_id >= 1);
    if (role_int == SERVER)
        inf->server_recv_cq = ibv_create_cq(
            inf->ctx, RSEC_CQ_DEPTH * inf->num_local_rcqps, NULL, NULL, 0);

    for (i = 0; i < inf->num_local_rcqps; i++) {
        inf->conn_cq[i] = ibv_create_cq(inf->ctx, RSEC_CQ_DEPTH, NULL, NULL, 0);
        assert(inf->conn_cq[i] != NULL);
        struct ibv_qp_init_attr create_attr;
        memset(&create_attr, 0, sizeof(struct ibv_qp_init_attr));
        create_attr.send_cq = inf->conn_cq[i];
        if (role_int == SERVER)
            create_attr.recv_cq = inf->server_recv_cq;
        else
            create_attr.recv_cq = inf->conn_cq[i];
        create_attr.qp_type = IBV_QPT_RC;

        create_attr.cap.max_send_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_recv_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_send_sge = RSEC_QP_MAX_SGE;
        create_attr.cap.max_recv_sge = RSEC_QP_MAX_SGE;
        create_attr.cap.max_inline_data = RSEC_MAX_INLINE;
        create_attr.sq_sig_all = 0;

        inf->conn_qp[i] = ibv_create_qp(inf->pd, &create_attr);
        assert(inf->conn_qp[i] != NULL);

        struct ibv_qp_attr init_attr;
        memset(&init_attr, 0, sizeof(struct ibv_qp_attr));
        init_attr.qp_state = IBV_QPS_INIT;
        init_attr.pkey_index = 0;
        init_attr.port_num = inf->dev_port_id;
        init_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE |
                                    IBV_ACCESS_REMOTE_READ |
                                    IBV_ACCESS_REMOTE_ATOMIC;
        if (ibv_modify_qp(inf->conn_qp[i], &init_attr,
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                              IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify conn QP to INIT\n");
            exit(-1);
        }
    }
}

/**
 * ib_create_udqps - setup RDMA UD qps
 */
void ib_create_udqps(struct ib_inf *inf)
    /*
       1. dgram_send\recv_cq: create cqs
       1. dgram_qp: change all qp to RTS
       2. dgram_buf[num_local_udpqs][UD_CQ_DEPTH]: malloc all elements and
       register memory
       */
{
    int i, j;
    assert(inf->dgram_qp != NULL && inf->dgram_send_cq != NULL &&
           inf->dgram_recv_cq != NULL && inf->pd != NULL && inf->ctx != NULL);
    assert(inf->num_local_udqps >= 1 && inf->dev_port_id >= 1);

    for (i = 0; i < inf->num_local_udqps; i++) {
        struct ibv_qp_init_attr create_attr;
        struct ibv_qp_attr init_attr;
        struct ibv_qp_attr rtr_attr;
        inf->dgram_send_cq[i] =
            ibv_create_cq(inf->ctx, RSEC_CQ_DEPTH, NULL, NULL, 0);
        assert(inf->dgram_send_cq[i] != NULL);

        inf->dgram_recv_cq[i] =
            ibv_create_cq(inf->ctx, RSEC_CQ_DEPTH, NULL, NULL, 0);
        assert(inf->dgram_recv_cq[i] != NULL);

        /* Initialize creation attributes */
        memset((void *)&create_attr, 0, sizeof(struct ibv_qp_init_attr));
        create_attr.send_cq = inf->dgram_send_cq[i];
        create_attr.recv_cq = inf->dgram_recv_cq[i];
        // dbg_printf("[%s] %lx %lx\n", __func__, (long unsigned
        // int)inf->dgram_send_cq[i], (long unsigned int)inf->dgram_recv_cq[i]);
        create_attr.qp_type = IBV_QPT_UD;

        create_attr.cap.max_send_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_recv_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_send_sge = 1;
        create_attr.cap.max_recv_sge = 1;
        create_attr.cap.max_inline_data = RSEC_MAX_INLINE;
        create_attr.sq_sig_all = 0;

        inf->dgram_qp[i] = ibv_create_qp(inf->pd, &create_attr);
        assert(inf->dgram_qp[i] != NULL);

        /* INIT state */
        memset((void *)&init_attr, 0, sizeof(struct ibv_qp_attr));
        init_attr.qp_state = IBV_QPS_INIT;
        init_attr.pkey_index = 0;
        init_attr.port_num = inf->dev_port_id;
        init_attr.qkey = RSEC_UD_QKEY;

        if (ibv_modify_qp(
                inf->dgram_qp[i], &init_attr,
                IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY)) {
            fprintf(stderr, "Failed to modify dgram QP to INIT\n");
            return;
        }

        /* RTR state */
        memset((void *)&rtr_attr, 0, sizeof(struct ibv_qp_attr));
        rtr_attr.qp_state = IBV_QPS_RTR;

        if (ibv_modify_qp(inf->dgram_qp[i], &rtr_attr, IBV_QP_STATE)) {
            fprintf(stderr, "Failed to modify dgram QP to RTR\n");
            exit(-1);
        }

        /* Reuse rtr_attr for RTS */
        rtr_attr.qp_state = IBV_QPS_RTS;
        rtr_attr.sq_psn = RSEC_UD_PSN;

        if (ibv_modify_qp(inf->dgram_qp[i], &rtr_attr,
                          IBV_QP_STATE | IBV_QP_SQ_PSN)) {
            fprintf(stderr, "Failed to modify dgram QP to RTS\n");
            exit(-1);
        }
        // create recv_buf for ud QPs
        inf->dgram_buf[i] = malloc(sizeof(void **) * RSEC_CQ_DEPTH);
        inf->dgram_buf_mr[i] = malloc(sizeof(struct ibv_mr *) * RSEC_CQ_DEPTH);
        for (j = 0; j < RSEC_CQ_DEPTH; j++) {
            inf->dgram_buf[i][j] =
                ib_malloc(sizeof(struct RSEC_message_frame) + UD_SHIFT_SIZE);
            assert(inf->dgram_buf[i][j] != NULL);
            inf->dgram_buf_mr[i][j] =
                ibv_reg_mr(inf->pd, inf->dgram_buf[i][j],
                           sizeof(struct RSEC_message_frame) + UD_SHIFT_SIZE,
                           IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                               IBV_ACCESS_REMOTE_READ);
            assert(inf->dgram_buf_mr[i][j] != NULL);
        }
    }
}

/**
 * ib_create_attackqps - setup different QP if users want to attack QP
 * [deprecated]
 */
void ib_create_attackqps(struct ib_inf *inf) {
    int i;
    assert(inf->attack_qp != NULL && inf->attack_cq != NULL &&
           inf->pd != NULL && inf->ctx != NULL);
    for (i = 0; i < inf->num_attack_rcqps; i++) {
        struct ibv_qp_init_attr create_attr;
        inf->attack_cq[i] =
            ibv_create_cq(inf->ctx, RSEC_CQ_DEPTH, NULL, NULL, 0);
        assert(inf->attack_cq[i] != NULL);
        memset(&create_attr, 0, sizeof(struct ibv_qp_init_attr));
        create_attr.send_cq = inf->attack_cq[i];
        create_attr.recv_cq = inf->attack_cq[i];
        create_attr.qp_type = IBV_QPT_RC;

        create_attr.cap.max_send_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_recv_wr = RSEC_CQ_DEPTH;
        create_attr.cap.max_send_sge = RSEC_QP_MAX_SGE;
        create_attr.cap.max_recv_sge = RSEC_QP_MAX_SGE;
        create_attr.cap.max_inline_data = RSEC_MAX_INLINE;

        inf->attack_qp[i] = ibv_create_qp(inf->pd, &create_attr);
        assert(inf->attack_qp[i] != NULL);

        struct ibv_qp_attr init_attr;
        memset(&init_attr, 0, sizeof(struct ibv_qp_attr));
        init_attr.qp_state = IBV_QPS_INIT;
        init_attr.pkey_index = 0;
        init_attr.port_num = inf->dev_port_id;
        init_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE |
                                    IBV_ACCESS_REMOTE_READ |
                                    IBV_ACCESS_REMOTE_ATOMIC;
        if (ibv_modify_qp(inf->attack_qp[i], &init_attr,
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                              IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify attack QP to INIT\n");
            exit(-1);
        }
    }
}

/**
 * ib_setup - the major function to setup ib conneciton
 * @id: machine id
 * @port: RDMA port
 * @num_rcqp_to_server: number of rc qps to a server
 * @num_rcqp_to_client: number of rc qps to a client
 * @num_udqps: number of udqps
 * @num_loopback: [deprecated]
 * @total_machines: number of total machines
 * @device_id: device id
 * @role_int: server/client
 */
struct ib_inf *ib_setup(int id, int port, int num_rcqp_to_server,
                        int num_rcqp_to_client, int num_udqps, int num_loopback,
                        int total_machines, int device_id, int role_int) {
    struct ib_inf *inf;
    struct ibv_device *ib_dev;
    int num_conn_qps;
    assert(port >= 0 && port <= 16);
    // assert(numa_node_id >= -1 && numa_node_id <= 8);
    assert(num_rcqp_to_server >= 0 &&
           num_rcqp_to_client > 0);  // at least one client/one memory
    assert(num_udqps > 0);           // at least one ud to server (one server)

    // assert(dgram_buf_size >= 0 && dgram_buf_size <= M_1024);

    if (num_udqps == 0) {
        die_printf("%s: error UDqps\n", __func__);
    }

    inf = (struct ib_inf *)malloc(sizeof(struct ib_inf));
    memset(inf, 0, sizeof(struct ib_inf));

    /* Fill in the control block */
    inf->local_id = id;
    inf->port_index = port;
    inf->device_id = device_id;
    inf->num_rc_qp_to_server = num_rcqp_to_server;
    inf->num_rc_qp_to_client = num_rcqp_to_client;

    num_conn_qps = num_rcqp_to_server + num_rcqp_to_client;
    inf->global_machines = total_machines;

    inf->num_local_rcqps = num_conn_qps;
    inf->num_global_rcqps = inf->global_machines * inf->num_local_rcqps;
    inf->num_local_udqps = num_udqps;
    inf->num_global_udqps = inf->global_machines * inf->num_local_udqps;

    /* Get the device to use. This fills in cb->device_id and cb->dev_port_id */
    ib_dev = ib_get_device(inf, port);
    CPE(!ib_dev, "IB device not found", 0);

    /* Use a single device context and PD for all QPs */
    inf->ctx = ibv_open_device(ib_dev);
    CPE(!inf->ctx, "Couldn't get context", 0);

    inf->pd = ibv_alloc_pd(inf->ctx);
    CPE(!inf->pd, "Couldn't allocate PD", 0);

    /* Create an array in cb for holding work completions */
    inf->wc = (struct ibv_wc *)malloc(RSEC_CQ_DEPTH * sizeof(struct ibv_wc));
    assert(inf->wc != NULL);
    memset(inf->wc, 0, RSEC_CQ_DEPTH * sizeof(struct ibv_wc));
    inf->all_rcqps = (struct ib_qp_attr **)malloc(inf->num_global_rcqps *
                                                  sizeof(struct ib_qp_attr *));

    inf->rcqp_buf =
        (uint64_t *)malloc(sizeof(uint64_t *) * inf->num_local_rcqps);
    inf->rcqp_buf_mr = (struct ibv_mr **)malloc(sizeof(struct ibv_mr **) *
                                                inf->num_local_rcqps);

    inf->all_udqps = (struct ib_qp_attr **)malloc(inf->num_global_udqps *
                                                  sizeof(struct ib_qp_attr *));
    inf->dgram_ah = (struct ibv_ah **)malloc(inf->num_global_udqps *
                                             sizeof(struct ibv_ah *));

    inf->dgram_buf = (void ***)malloc(sizeof(void **) * inf->num_local_udqps);
    inf->dgram_buf_mr = (struct ibv_mr ***)malloc(sizeof(struct ibv_mr **) *
                                                  inf->num_local_udqps);

    /*
     * Create datagram QPs and transition them RTS.
     * Create and register datagram RDMA buffer.
     */
    if (inf->num_local_udqps >= 1) {
        inf->dgram_qp = (struct ibv_qp **)malloc(inf->num_local_udqps *
                                                 sizeof(struct ibv_qp *));
        inf->dgram_send_cq = (struct ibv_cq **)malloc(inf->num_local_udqps *
                                                      sizeof(struct ibv_cq *));
        inf->dgram_recv_cq = (struct ibv_cq **)malloc(inf->num_local_udqps *
                                                      sizeof(struct ibv_cq *));

        assert(inf->dgram_qp != NULL && inf->dgram_send_cq != NULL &&
               inf->dgram_recv_cq != NULL);
        ib_create_udqps(inf);
    }
    /*
     * Create connected QPs and transition them to RTS.
     * Create and register connected QP RDMA buffer.
     */
    if (inf->num_local_rcqps >= 1) {
        inf->conn_qp = (struct ibv_qp **)malloc(inf->num_local_rcqps *
                                                sizeof(struct ibv_qp *));
        inf->conn_cq = (struct ibv_cq **)malloc(inf->num_local_rcqps *
                                                sizeof(struct ibv_cq *));
        assert(inf->conn_qp != NULL && inf->conn_cq != NULL);
        ib_create_rcqps(inf, role_int);
    }
    // Create counter
    inf->ud_qp_counter = malloc(sizeof(uint64_t) * inf->num_local_udqps);
    memset(inf->ud_qp_counter, 0, sizeof(uint64_t) * inf->num_local_udqps);
    inf->rc_qp_counter = malloc(sizeof(uint64_t) * inf->num_local_rcqps);
    memset(inf->rc_qp_counter, 0, sizeof(uint64_t) * inf->num_local_rcqps);
    // loopback setup
    inf->loopback_in_qp = malloc(sizeof(struct ibv_qp *) * num_loopback);
    inf->loopback_out_qp = malloc(sizeof(struct ibv_qp *) * num_loopback);
    inf->loopback_in_qp_attr = malloc(sizeof(struct ib_qp_attr) * num_loopback);
    inf->loopback_out_qp_attr =
        malloc(sizeof(struct ib_qp_attr) * num_loopback);
    inf->loopback_cq = malloc(sizeof(struct ibv_cq *) * num_loopback);
    inf->num_loopback = num_loopback;

    // setup gid which would be used by RoCE
    if (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) {
        inf->local_gid = ib_get_gid(inf->ctx, inf->port_index);
    }

    return inf;
}

/**
 * ib_local_setup - the sub function to setup ib conneciton - majorly setup
 * buffer
 * @input_arg: input parameter
 * @inf: context from ib_setup
 */
struct ib_local_inf *ib_local_setup(struct configuration_params *input_arg,
                                    struct ib_inf *inf) {
    struct ib_local_inf *ret_local_inf = malloc(sizeof(struct ib_local_inf));
    int i;
    uint32_t alloc_size = RSEC_LOCAL_BUF_ALLOC_SIZE;
    assert(ret_local_inf != 0);
    ret_local_inf->thread_id = input_arg->local_thread_id;
    ret_local_inf->send_buf =
        (void **)malloc(sizeof(void *) * RSEC_THREAD_SEND_BUF_NUM);
    ret_local_inf->send_buf_mr = (struct ibv_mr **)malloc(
        sizeof(struct ibv_mr *) * RSEC_THREAD_SEND_BUF_NUM);
    ret_local_inf->machine_id = input_arg->machine_id;

    for (i = 0; i < RSEC_THREAD_SEND_BUF_NUM; i++) {
        ret_local_inf->send_buf[i] = ib_malloc(alloc_size);
        assert(ret_local_inf->send_buf[i] != NULL);
        ret_local_inf->send_buf_mr[i] =
            ibv_reg_mr(inf->pd, ret_local_inf->send_buf[i], alloc_size,
                       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                           IBV_ACCESS_REMOTE_READ);
        assert(ret_local_inf->send_buf_mr[i] != NULL);
    }
    ret_local_inf->recv_buf =
        (void **)malloc(sizeof(void *) * RSEC_THREAD_RECV_BUF_NUM);
    ret_local_inf->recv_buf_mr = (struct ibv_mr **)malloc(
        sizeof(struct ibv_mr *) * RSEC_THREAD_RECV_BUF_NUM);
    for (i = 0; i < RSEC_THREAD_RECV_BUF_NUM; i++) {
        ret_local_inf->recv_buf[i] = ib_malloc(alloc_size);
        assert(ret_local_inf->recv_buf[i] != NULL);
        ret_local_inf->recv_buf_mr[i] =
            ibv_reg_mr(inf->pd, ret_local_inf->recv_buf[i], alloc_size,
                       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                           IBV_ACCESS_REMOTE_READ);
        assert(ret_local_inf->recv_buf_mr[i] != NULL);
    }

    ret_local_inf->global_thread_id = input_arg->global_thread_id;
    ret_local_inf->local_thread_id = input_arg->local_thread_id;

    ret_local_inf->current_metadata_offset = 0;
    ret_local_inf->current_data_offset = 0;

    return ret_local_inf;
}

/**
 * ib_post_recv_connect_qp - post_recv target connect QP
 */
int ib_post_recv_connect_qp(struct ib_inf *context,
                            ib_post_recv_inf *post_recv_inf_list,
                            struct ib_mr_attr *input_mr_array,
                            int input_mr_array_length) {
    int i;
    int ret;
    for (i = 0; i < input_mr_array_length;
         i++)  // need optimization to remove multiple post-recves
    {
        struct ibv_recv_wr recv_wr, *bad_wr;
        struct ibv_sge recv_sge;
        recv_sge.addr = input_mr_array[i].addr;
        recv_sge.lkey = input_mr_array[i].rkey;
        recv_sge.length = post_recv_inf_list[i].length;
        recv_wr.wr_id = RSEC_ID_COMBINATION(post_recv_inf_list[i].qp_index,
                                            post_recv_inf_list[i].mr_index);
        recv_wr.sg_list = &recv_sge;
        recv_wr.num_sge = 1;
        recv_wr.next = NULL;
        assert(context->conn_qp[post_recv_inf_list[i].qp_index] != 0);
        assert(recv_sge.addr);
        assert(recv_sge.lkey);

        ret = ibv_post_recv(context->conn_qp[post_recv_inf_list[i].qp_index],
                            &recv_wr, &bad_wr);
        CPE(ret, "ibv_post_recv error", ret);
        if (ret) return -ret;
    }
    return i;
}

/**
 * ib_complete_setup - finalize all RDMA configurations
 */
struct ib_inf *ib_complete_setup(struct configuration_params *input_arg,
                                 int role_int, char *role_str) {
    int machine_id;
    struct ib_inf *node_share_inf;
    int i, j;
    int cumulative_id = 0, total_machines, total_qp_count = 0;

    total_machines = input_arg->num_servers + input_arg->num_clients;
    machine_id = input_arg->machine_id;
    node_share_inf = ib_setup(input_arg->machine_id, input_arg->base_port_index,
                              input_arg->num_servers * RSEC_PARALLEL_RC_QPS,
                              input_arg->num_clients * RSEC_PARALLEL_RC_QPS,
                              RSEC_PARALLEL_UD_QPS, input_arg->num_loopback,
                              total_machines, input_arg->device_id, role_int);

    node_share_inf->num_servers = input_arg->num_servers;
    node_share_inf->num_clients = input_arg->num_clients;
    node_share_inf->device_id = input_arg->device_id;
    node_share_inf->role = role_int;

    // post all rc qps
    for (i = 0; i < node_share_inf->num_local_rcqps; i++) {
        char srv_name[RSEC_MAX_QP_NAME];
        sprintf(srv_name, "machine-rc-%d-%d", machine_id, i);
        memcached_publish_rcqp(node_share_inf, i, srv_name);
        // RSEC_PRINT("publish %s\n", srv_name);
    }
    // get all published rc qps
    for (cumulative_id = 0; cumulative_id < total_machines; cumulative_id++) {
        for (i = 0; i < node_share_inf->num_local_rcqps; i++) {
            char srv_name[RSEC_MAX_QP_NAME];
            sprintf(srv_name, "machine-rc-%d-%d", cumulative_id, i);
            node_share_inf->all_rcqps[total_qp_count] =
                memcached_get_published_qp(srv_name);
            total_qp_count++;
        }
        RSEC_PRINT("get machine %d/%d\n", cumulative_id, total_machines);
    }
    // connected all rc queue pairs
    total_qp_count = 0;
    for (i = 0; i < total_machines; i++) {
        for (j = 0; j < RSEC_PARALLEL_RC_QPS; j++) {
            if (i == machine_id) {
                total_qp_count++;
                continue;
            }
            int target_qp_num = i * total_machines * RSEC_PARALLEL_RC_QPS +
                                machine_id * RSEC_PARALLEL_RC_QPS + j;
            /*dbg_printf(
                    "connect %d(%d): lid:%d qpn:%d sl:%d rkey:%lu\n",
                    total_qp_count,
                    target_qp_num,
                    node_share_inf->all_rcqps[target_qp_num]->lid,
                    node_share_inf->all_rcqps[target_qp_num]->qpn,
                    node_share_inf->all_rcqps[target_qp_num]->sl,
                    node_share_inf->all_rcqps[target_qp_num]->rkey
                    );*/
            ib_connect_qp(node_share_inf, total_qp_count,
                          node_share_inf->all_rcqps[target_qp_num]);
            total_qp_count++;
        }
    }

    total_qp_count = 0;
    // post all ud qp
    for (i = 0; i < node_share_inf->num_local_udqps; i++) {
        char srv_name[RSEC_MAX_QP_NAME];
        sprintf(srv_name, "machine-ud-%d-%d", machine_id, i);
        memcached_publish_udqp(node_share_inf, i, srv_name);
    }
    // get all published ud qps
    for (cumulative_id = 0; cumulative_id < total_machines; cumulative_id++) {
        for (i = 0; i < node_share_inf->num_local_udqps; i++) {
            char srv_name[RSEC_MAX_QP_NAME];
            sprintf(srv_name, "machine-ud-%d-%d", cumulative_id, i);
            node_share_inf->all_udqps[total_qp_count] =
                memcached_get_published_qp(srv_name);
            total_qp_count++;
        }
        // dbg_printf("get machine UD %d\n", cumulative_id);
    }
    // connected all UD queue pairs
    RSEC_PRINT("done %s\n", role_str);
    // post_recv for local UD
    for (i = 0; i < node_share_inf->num_local_udqps; i++) {
        int ret;
        ret = ib_post_recv_ud_qp(node_share_inf, i, 0, RSEC_CQ_DEPTH);
        if (ret != RSEC_CQ_DEPTH) {
            die_printf("[%s] fail to post recv UD QP %d ret %d\n", __func__, i,
                       ret);
            exit(1);
        }
    }
    node_share_inf->local_memid = 0;

    // setup attack qps

    node_share_inf->num_attack_rcqps = input_arg->num_attack_qps;
    if (input_arg->num_attack_qps) {
        node_share_inf->attack_rcqps = (struct ib_qp_attr **)malloc(
            node_share_inf->num_attack_rcqps * sizeof(struct ib_qp_attr *));
        node_share_inf->attack_qp = (struct ibv_qp **)malloc(
            node_share_inf->num_attack_rcqps * sizeof(struct ibv_qp *));
        node_share_inf->attack_cq = (struct ibv_cq **)malloc(
            node_share_inf->num_attack_rcqps * sizeof(struct ibv_cq *));
        ib_create_attackqps(node_share_inf);
    }

    // connect attack qp

    if (input_arg->num_attack_qps) {
        int server_flag = 0;
        if (input_arg->machine_id == 0)
            server_flag = 1;
        else
            server_flag = 0;
        for (i = 0; i < node_share_inf->num_attack_rcqps; i++) {
            char srv_name[RSEC_MAX_QP_NAME];
            if (server_flag)  // server
                sprintf(srv_name, RSEC_ATTACK_QP_STRING_SERVER, i);
            else
                sprintf(srv_name, RSEC_ATTACK_QP_STRING_ATTACKER, i);
            memcached_publish_attackqp(node_share_inf, i, srv_name);
        }

        // get all published attack qps
        for (i = 0; i < node_share_inf->num_attack_rcqps; i++) {
            char srv_name[RSEC_MAX_QP_NAME];
            if (server_flag)
                sprintf(srv_name, RSEC_ATTACK_QP_STRING_ATTACKER, i);
            else
                sprintf(srv_name, RSEC_ATTACK_QP_STRING_SERVER, i);
            node_share_inf->attack_rcqps[i] =
                memcached_get_published_qp(srv_name);
        }
        RSEC_PRINT("get machine attacker qp %d\n", input_arg->num_attack_qps);
        // connected all attack queue pairs
        for (i = 0; i < node_share_inf->num_attack_rcqps; i++) {
            struct ib_qp_attr *dest = node_share_inf->attack_rcqps[i];
            struct ibv_qp_attr attr = {
                .qp_state = IBV_QPS_RTR,
                .path_mtu = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE)
                                ? IBV_MTU_1024
                                : IBV_MTU_4096,
                .dest_qp_num = dest->qpn,
                .rq_psn = RSEC_UD_PSN,
                .max_dest_rd_atomic = 10,
                .min_rnr_timer = 12,
                .ah_attr = {
                    .is_global =
                        (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? 1 : 0,
                    .dlid = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE)
                                ? 0
                                : dest->lid,
                    .sl = dest->sl,
                    .src_path_bits = 0,
                    .port_num = node_share_inf->port_index}};
            if (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) {
                attr.ah_attr.grh.dgid.global.interface_id =
                    dest->remote_gid.global.interface_id;
                attr.ah_attr.grh.dgid.global.subnet_prefix =
                    dest->remote_gid.global.subnet_prefix;
                attr.ah_attr.grh.sgid_index = RSEC_SGID_INDEX;
                attr.ah_attr.grh.hop_limit = 1;
            }
            if (ibv_modify_qp(node_share_inf->attack_qp[i], &attr,
                              IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                                  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                  IBV_QP_MAX_DEST_RD_ATOMIC |
                                  IBV_QP_MIN_RNR_TIMER)) {
                fprintf(stderr, "[%s] Failed to modify QP to RTR\n", __func__);
            }
            attr.qp_state = IBV_QPS_RTS;
            attr.timeout = 14;
            attr.retry_cnt = 7;
            attr.rnr_retry = 7;
            attr.sq_psn = RSEC_UD_PSN;
            attr.max_rd_atomic = 16;
            attr.max_dest_rd_atomic = 16;
            if (ibv_modify_qp(node_share_inf->attack_qp[i], &attr,
                              IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                                  IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                                  IBV_QP_MAX_QP_RD_ATOMIC)) {
                fprintf(stderr, "[%s] Failed to modify QP to RTS\n", __func__);
            }
        }
        RSEC_PRINT("connect machine attacker qp %d\n",
                   input_arg->num_attack_qps);
    }

    return node_share_inf;
}

/**
 * ib_connect_qp: connect local qp to remote QP
 * @inf: RDMA context
 * @qp_index: local qp index
 * @dest: remote QP information
 */
int ib_connect_qp(struct ib_inf *inf, int qp_index, struct ib_qp_attr *dest)
    /*
       1.change conn_qp to RTS
       */
{
    struct ibv_qp_attr attr = {
        .qp_state = IBV_QPS_RTR,
        .path_mtu = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? IBV_MTU_1024
                                                             : IBV_MTU_4096,
        .dest_qp_num = dest->qpn,
        .rq_psn = RSEC_UD_PSN,
        .max_dest_rd_atomic = 10,
        .min_rnr_timer = 12,
        .ah_attr = {
            .is_global = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? 1 : 0,
            .dlid = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? 0 : dest->lid,
            .sl = dest->sl,
            .src_path_bits = 0,
            .port_num = inf->port_index}};
    if (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) {
        // attr.ah_attr.grh.dgid.global.interface_id =
        // dest->remote_gid.global.interface_id;
        // attr.ah_attr.grh.dgid.global.subnet_prefix =
        // dest->remote_gid.global.subnet_prefix;
        attr.ah_attr.grh.dgid = dest->remote_gid;
        attr.ah_attr.grh.sgid_index = RSEC_SGID_INDEX;
        attr.ah_attr.grh.hop_limit = 1;
    }
    if (ibv_modify_qp(inf->conn_qp[qp_index], &attr,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                          IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                          IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER)) {
        fprintf(stderr, "[%s] Failed to modify QP to RTR\n", __func__);
        return 1;
    }
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = RSEC_UD_PSN;
    attr.max_rd_atomic = 16;
    attr.max_dest_rd_atomic = 16;
    if (ibv_modify_qp(inf->conn_qp[qp_index], &attr,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                          IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
                          IBV_QP_MAX_QP_RD_ATOMIC)) {
        fprintf(stderr, "[%s] Failed to modify QP to RTS\n", __func__);
        return 2;
    }
    return 0;
}

/**
 * ib_create_ah_for_ud: create address handler for UD queue pair
 */
struct ibv_ah *ib_create_ah_for_ud(struct ib_inf *inf, int ah_index,
                                   struct ib_qp_attr *dest) {
    struct ibv_ah_attr ah_attr = {
        .is_global = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? 1 : 0,
        .dlid = (RSEC_NETWORK_MODE == RSEC_NETWORK_ROCE) ? 0 : dest->lid,
        .sl = RSEC_UD_SL,
        .src_path_bits = 0,
        .port_num = inf->port_index};
    struct ibv_ah *tar_ah = ibv_create_ah(inf->pd, &ah_attr);
    return tar_ah;
}

/**
 * ib_poll_cq: poll target cq
 */
inline int ib_poll_cq(struct ibv_cq *cq, int num_comps, struct ibv_wc *wc) {
    int comps = 0;

    while (comps < num_comps) {
        int new_comps = ibv_poll_cq(cq, num_comps - comps, &wc[comps]);
        if (new_comps != 0) {
            // Ideally, we should check from comps -> new_comps - 1
            if (wc[comps].status != 0) {
                fprintf(stderr, "Bad wc status %d\n", wc[comps].status);
                exit(0);
                return 1;
                // exit(0);
            }
            comps += new_comps;
        }
    }
    return 0;
}

/**
 * userspace_one_write: issue one write request
 */
int userspace_one_write(struct ibv_qp *qp, struct ibv_mr *local_mr,
                        int request_size, struct ib_mr_attr *remote_mr,
                        unsigned long long offset) {
    struct ibv_sge test_sge;
    struct ibv_send_wr wr, *bad_send_wr;
    int ret;
    test_sge.length = request_size;
    test_sge.addr = (uintptr_t)local_mr->addr;
    test_sge.lkey = local_mr->lkey;
    wr.opcode = IBV_WR_RDMA_WRITE;
    wr.num_sge = 1;
    wr.next = NULL;
    wr.sg_list = &test_sge;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr_id = 0;
    wr.wr.rdma.remote_addr = remote_mr->addr + offset;
    wr.wr.rdma.rkey = remote_mr->rkey;
    ret = ibv_post_send(qp, &wr, &bad_send_wr);
    CPE(ret, "ibv_post_send error", ret);
    return 0;
}

/**
 * userspace_one_preset: issue one request with a pre-configured wrt
 */
int userspace_one_preset(struct ibv_qp *qp, struct ibv_send_wr *wr) {
    struct ibv_send_wr *bad_send_wr;
    int ret;
    ret = ibv_post_send(qp, wr, &bad_send_wr);
    CPE(ret, "ibv_post_send error", ret);
    return 0;
}

/**
 * userspace_one_send: issue one RDMA send request
 */
int userspace_one_send(struct ibv_qp *qp, struct ibv_mr *local_mr,
                       int request_size) {
    struct ibv_sge test_sge;
    struct ibv_send_wr wr, *bad_send_wr;
    int ret;
    test_sge.length = request_size;
    test_sge.addr = (uintptr_t)local_mr->addr;
    test_sge.lkey = local_mr->lkey;
    wr.opcode = IBV_WR_SEND;
    wr.num_sge = 1;
    wr.next = NULL;
    wr.sg_list = &test_sge;
    wr.send_flags = IBV_SEND_SIGNALED;
    ret = ibv_post_send(qp, &wr, &bad_send_wr);
    CPE(ret, "ibv_post_send error", ret);
    return 0;
}

/**
 * userspace_one_read: issue one RDMA read request
 */
int userspace_one_read(struct ibv_qp *qp, struct ibv_mr *local_mr,
                       int request_size, struct ib_mr_attr *remote_mr,
                       unsigned long long offset) {
    struct ibv_sge test_sge;
    struct ibv_send_wr wr, *bad_send_wr;
    int ret;
    test_sge.length = request_size;
    test_sge.addr = (uintptr_t)local_mr->addr;
    test_sge.lkey = local_mr->lkey;
    wr.opcode = IBV_WR_RDMA_READ;
    wr.num_sge = 1;
    wr.next = NULL;
    wr.sg_list = &test_sge;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_mr->addr + offset;
    wr.wr.rdma.rkey = remote_mr->rkey;
    ret = ibv_post_send(qp, &wr, &bad_send_wr);
    CPE(ret, "ibv_post_send error", ret);
    return 0;
}

/**
 * userspace_one_poll: poll target CQ
 */
int userspace_one_poll(struct ibv_cq *cq, int tar_mem) {
    struct ibv_wc wc[RSEC_CQ_DEPTH];
    return ib_poll_cq(cq, tar_mem, wc);
}

/**
 * userspace_one_poll_wr: poll with returned wc
 */
inline int userspace_one_poll_wr(struct ibv_cq *cq, int tar_mem,
                                 struct ibv_wc *input_wc) {
    ib_poll_cq(cq, tar_mem, input_wc);
    return tar_mem;
}
