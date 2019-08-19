#ifndef RSEC_SERVER
#define RSEC_SERVER
#include "rsec_base.h"
void *run_server(void *arg);
void *main_server(void *arg);
void server_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg);
void helper_code(struct ib_inf *global_inf, struct ib_local_inf *local_inf,
                 struct configuration_params *input_arg);

void rc_write_local(struct ib_inf *global_inf, struct ib_local_inf *local_inf);
void rc_recv_server(struct ib_inf *global_inf);
#endif
