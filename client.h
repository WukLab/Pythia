
#ifndef RSEC_CLIENT
#define RSEC_CLIENT
#include "rsec_base.h"
void *run_client(void *arg);
void *main_client(void *arg);
void client_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg);
void attacker_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                   struct configuration_params *input_arg);

void rc_send_client(struct ib_inf *global_inf);
int post_write(struct ib_inf *inf, int rcqp_index, struct ib_qp_attr *dest,
               struct timespec *, int);
#endif
