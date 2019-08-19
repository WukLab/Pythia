#include "rsec.h"
void dbg_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void die_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(1);
}

double count, sum_time;
pthread_spinlock_t sum_diff_ns_lock;
double sum_diff_ns(struct timespec *start, struct timespec *end, int flag) {
    double ret;
    double time;
    if (flag == 0) {
        time = (end->tv_sec - start->tv_sec) * 1000 * 1000 * 1000;
        time += (end->tv_nsec - start->tv_nsec);
        pthread_spin_lock(&sum_diff_ns_lock);
        count++;
        sum_time += time;
        pthread_spin_unlock(&sum_diff_ns_lock);
        return time;
    } else if (flag == 1) {
        ret = pthread_spin_init(&sum_diff_ns_lock, 0);
        count = 0;
        sum_time = 0;
        return ret;
    } else if (flag == 2) {
        pthread_spin_lock(&sum_diff_ns_lock);
        printf("[sum] sum:%f count:%f average:%f\n", sum_time, count,
               sum_time / count);
        pthread_spin_unlock(&sum_diff_ns_lock);
        return 0;
    } else
        return 0;
}

double diff_ns(struct timespec *start, struct timespec *end) {
    double time;

    time = (end->tv_sec - start->tv_sec) * 1000 * 1000 * 1000;
    time += (end->tv_nsec - start->tv_nsec);

    return time;
}

double current_ms(struct timespec *start) {
    double time;

    time = (start->tv_sec) * 1000;
    time += (start->tv_nsec) / (1000 * 1000);

    return time;
}

int stick_this_thread_to_core(int core_id) {
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (core_id < 0 || core_id >= num_cores) return EINVAL;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t current_thread = pthread_self();
    return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

void array_swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

// A function to generate a random permutation of arr[]
void array_randomize(int arr[], int n) {
    int i;
    // Use a different seed value so that we don't get same
    // result each time we run this program
    // srand ( time(NULL) );

    // Start from the last element and swap one by one. We don't
    // need to run for the first element that's why i > 0
    for (i = n - 1; i > 0; i--) {
        // Pick a random index from 0 to i
        int j = rand() % (i + 1);

        // Swap arr[i] with the element at random index
        array_swap(&arr[i], &arr[j]);
    }
}

void get_file(char **op, int **key, char *path_string, int test_times) {
    int *write_key;
    char *op_key;
    FILE *fp;
    char filepath[32];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int i;
    i = 0;
    sprintf(filepath, "%s", path_string);
    printf("[UTIL] start reading %s %d\n", filepath, test_times);
    fflush(stdout);
    fp = fopen(filepath, "r");
    if (!fp) {
        printf("[ERROR] fail to open %s\n", path_string);
        return;
    }
    op_key = malloc(sizeof(char) * test_times);
    write_key = malloc(sizeof(int) * test_times);
    while ((read = getline(&line, &len, fp)) != -1) {
        sscanf(line, "%c %llu\n", &op_key[i],
               (long long unsigned int *)&write_key[i]);
        i++;
        if (i == test_times) break;
    }
    printf("[UTIL] finish reading %s %d\n", filepath, test_times);
    fflush(stdout);
    *op = op_key;
    *key = write_key;
}
