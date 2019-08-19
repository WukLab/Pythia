#ifndef RSEC_IBSETUP_HEADER
#define RSEC_IBSETUP_HEADER
#include <infiniband/verbs.h>
#include "rsec_struct.h"

#define RSEC_NETWORK_IB 1
#define RSEC_NETWORK_ROCE 2
#define RSEC_NETWORK_MODE RSEC_NETWORK_IB
//#define RSEC_NETWORK_MODE RSEC_NETWORK_ROCE

#define RSEC_SGID_INDEX 3

#define RSEC_ID_COMBINATION(qp_index, i) ((qp_index << 16) + i)
#define RSEC_ID_TO_QP(wr_id) (wr_id >> 16)
#define RSEC_ID_TO_RECV_MR(wr_id) (wr_id & 0xffff)

struct ib_post_recv_inf {
    uint64_t mr_index;
    int qp_index;
    int length;
};
typedef struct ib_post_recv_inf ib_post_recv_inf;

int test(int);
union ibv_gid ib_get_gid(struct ibv_context *context, int port_index);
struct ibv_device *ib_get_device(struct ib_inf *inf, int port);
void ib_create_udqps(struct ib_inf *inf);
struct ib_inf *ib_setup(int id, int port, int num_rcqp_to_server,
                        int num_rcqp_to_client, int num_udqps, int num_loopback,
                        int total_machines, int device_id, int role_int);
uint16_t ib_get_local_lid(struct ibv_context *ctx, int dev_port_id);
int ib_connect_qp(struct ib_inf *inf, int qp_index, struct ib_qp_attr *qp_attr);
struct ibv_ah *ib_create_ah_for_ud(struct ib_inf *inf, int ah_index,
                                   struct ib_qp_attr *dest);
struct ib_inf *ib_complete_setup(struct configuration_params *input_arg,
                                 int role_int, char *role_str);
void ib_create_rcqps(struct ib_inf *inf, int role_int);
void ib_create_attackqps(struct ib_inf *inf);
struct ib_local_inf *ib_local_setup(struct configuration_params *input_arg,
                                    struct ib_inf *inf);
void *ib_malloc(size_t length);
int ib_post_recv_ud_qp(struct ib_inf *inf, int udqp_index, int post_recv_base,
                       int post_recv_num);
void ib_create_connect_loopback(struct ib_inf *inf);

int ib_post_recv_connect_qp(struct ib_inf *context,
                            ib_post_recv_inf *post_recv_inf_list,
                            struct ib_mr_attr *input_mr_array,
                            int input_mr_array_length);

inline int ib_poll_cq(struct ibv_cq *cq, int num_comps, struct ibv_wc *wc);
int userspace_one_send(struct ibv_qp *qp, struct ibv_mr *local_mr,
                       int request_size);
int userspace_one_read(struct ibv_qp *qp, struct ibv_mr *local_mr,
                       int request_size, struct ib_mr_attr *remote_mr,
                       unsigned long long offset);
int userspace_one_write(struct ibv_qp *qp, struct ibv_mr *local_mr,
                        int request_size, struct ib_mr_attr *remote_mr,
                        unsigned long long offset);
int userspace_one_poll(struct ibv_cq *cq, int tar_mem);
inline int userspace_one_poll_wr(struct ibv_cq *cq, int tar_mem,
                                 struct ibv_wc *input_wc);

int userspace_one_preset(struct ibv_qp *qp, struct ibv_send_wr *wr);
#endif
