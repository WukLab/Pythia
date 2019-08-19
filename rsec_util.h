#ifndef RSEC_UTIL_HEADER
#define RSEC_UTIL_HEADER

#define RSEC_WHOLE_DEBUG
#ifdef RSEC_WHOLE_DEBUG
#define RSEC_PRINT(string, args...) \
    printf("[R_SECURITY] %s:%d :\t" string, __func__, __LINE__, ##args)
#define RSEC_FPRINT(fp, string, args...) \
    fprintf(fp, "[R_SECURITY] %s:%d :\t" string, __func__, __LINE__, ##args)
#define RSEC_PRINT_BRIEF(string, args...) printf("[R_SECURITY] " string, ##args)
#define RSEC_ERROR(string, args...) \
    printf("[R_SECURITY-ERROR] %s:%d : " string, __func__, __LINE__, ##args)
#define RSEC_INFO(string, args...) \
    printf("[R_SECURITY] %s:%d : " string, __func__, __LINE__, ##args)
#else
#define RSEC_PRINT(string, args...)
#define RSEC_PRINT_BRIEF(string, args...)
#define RSEC_ERROR(string, args...) printf("[R_SECURITY-ERROR] " string, ##args)
#define RSEC_INFO(string, args...) printf("[R_SECURITY] " string, ##args)
#endif

#define CPE(val, msg, err_code)                    \
    if (val) {                                     \
        fprintf(stderr, msg);                      \
        fprintf(stderr, " Error %d \n", err_code); \
        exit(err_code);                            \
    }

//#define RSEC_MIN(a, b) (((a) < (b)) ? (a) : (b))
//#define RSEC_MAX(a, b) (((a) > (b)) ? (a) : (b))
//#define RSEC_ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

#endif
