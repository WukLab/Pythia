#ifndef RSEC_BASE_HEADER_FILE
#define RSEC_BASE_HEADER_FILE

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <infiniband/verbs.h>
#include "rsec.h"
#define OFFSET (0x0)
//#include<glib.h>

#define SERVER 128
#define CLIENT 129
#define MEMORY 130
#define UD_SHIFT_SIZE 40

#define RSEC_LOCAL_BUF_ALLOC_SIZE 1024

// IB-related def

#define FORCE_POLL 1

#define RSEC_ID_SHIFT 10

#define RSEC_PARALLEL_RC_QPS 1
#define RSEC_PARALLEL_UD_QPS 1
#define RSEC_MAX_INLINE 0

#define RSEC_UD_QKEY 0x7777
#define RSEC_UD_PSN 3185
#define RSEC_UD_SL 0

#define RSEC_RC_SL 0

#define RSEC_UD_POST_RECV_ID_SHIFT 48

#define RSEC_THREAD_SEND_BUF_NUM 16
#define RSEC_THREAD_RECV_BUF_NUM 16

#endif
