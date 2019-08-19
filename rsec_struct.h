#ifndef RSEC_STRUCT_HEADER
#define RSEC_STRUCT_HEADER

#include <infiniband/verbs.h>

// Memcached
#define RSEC_MAX_QP_NAME 256
#define RSEC_RESERVED_NAME_PREFIX "__RSEC_RESERVED_NAME_PREFIX"
#define MEMCACHED_IP "10.10.1.4"

#define RSEC_CQ_DEPTH 1024
#define RSEC_QP_MAX_SGE 2

#define RSEC_DATA_SIZE (1 << 9)
#define RSEC_NONCE_LENGTH 16
#define RSEC_AES_BLOCK_SIZE 16

struct return_int {
    long int first;
    long int last;
    long int index_distance;
    long int real_distance;
};

struct ib_qp_attr {
    char name[RSEC_MAX_QP_NAME];

    /* Info about the RDMA buffer associated with this QP */
    uint64_t buf_addr;
    uint32_t buf_size;
    uint32_t rkey;
    int sl;

    int lid;
    int qpn;

    union ibv_gid remote_gid;
};

struct ib_mr_attr {
    uint64_t addr;
    uint32_t rkey;
};

struct configuration_params {
    int global_thread_id;
    int local_thread_id;
    int base_port_index;
    int num_servers;
    int num_clients;
    int is_master;
    int machine_id;
    int total_threads;
    int device_id;
    int num_loopback;
    int interaction_mode;
    int num_attack_qps;
};

struct RSEC_message_frame {
    char msg[1 << 15];
};

struct ib_inf {

    int local_id; /* Local ID on the machine this process runs on */
    int global_machines;
    int local_threads;

    /* Info about the device/port to use for this control block */
    struct ibv_context *ctx;
    int port_index; /* User-supplied. 0-based across all devices */
    int device_id;
    int dev_port_id;
    int numa_node_id; /* NUMA node id */

    struct ibv_pd *pd; /* A protection domain for this control block */

    int role;  // SERVER, CLIENT and MEMORY

    int num_servers;
    int num_clients;
    int num_memorys;

    /* Connected QPs */
    int num_rc_qp_to_server;
    int num_rc_qp_to_client;
    int num_rc_qp_to_memory;
    int num_local_rcqps;
    int num_global_rcqps;
    struct ibv_qp **conn_qp;
    struct ibv_cq **conn_cq, *server_recv_cq;
    struct ib_qp_attr **all_rcqps;

    uint64_t *rcqp_buf;
    struct ibv_mr **rcqp_buf_mr;
    // volatile uint8_t *conn_buf;
    // int conn_buf_size;
    // int conn_buf_shm_key;
    // struct ibv_mr *conn_buf_mr;

    /* Datagram QPs */
    struct ibv_qp **dgram_qp;
    struct ibv_cq **dgram_send_cq, **dgram_recv_cq;
    struct ib_qp_attr **all_udqps;
    struct ibv_ah **dgram_ah;
    int num_local_udqps;
    int num_global_udqps;
    void ***dgram_buf; /* A buffer for RECVs on dgram QPs */
    struct ibv_mr ***dgram_buf_mr;
    int dgram_buf_size;
    // int dgram_buf_shm_key;
    struct ibv_wc *wc; /* Array of work completions */

    /* loopback QPs */
    struct ibv_qp **loopback_in_qp;
    struct ibv_qp **loopback_out_qp;
    struct ibv_cq **loopback_cq;
    struct ib_qp_attr *loopback_in_qp_attr;
    struct ib_qp_attr *loopback_out_qp_attr;
    int num_loopback;

    uint64_t *ud_qp_counter;
    uint64_t *rc_qp_counter;

    uint64_t local_memid;

    // GHashTable *mr_hash_table;
    // GHashTable *file_hash_table;
    pthread_mutex_t hash_lock;

    // attack qp
    int num_attack_rcqps;
    struct ibv_qp **attack_qp;
    struct ibv_cq **attack_cq;
    struct ib_qp_attr **attack_rcqps;

    union ibv_gid local_gid;
};

struct ib_local_inf {
    int thread_id;
    int machine_id;
    struct ibv_mr **send_buf_mr;
    void **send_buf;

    struct ibv_mr **recv_buf_mr;
    void **recv_buf;
    int global_thread_id;
    int local_thread_id;

    uint32_t current_metadata_memnode;
    uint32_t current_metadata_memid;
    uint32_t current_metadata_offset;

    uint32_t current_data_memnode;
    uint32_t current_data_memid;
    uint32_t current_data_offset;
};

struct rsec_malloc_metadata {
    void *addr;
    unsigned long size;
};

#endif
