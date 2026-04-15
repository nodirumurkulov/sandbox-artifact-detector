#include "timing.h"
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <x86intrin.h>
#endif

// Helper function to get current time in milliseconds
static uint64_t get_time_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000) / frequency.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}

// High-resolution timer returning milliseconds as a double (sub-ms precision)
static double get_time_precise_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#endif
}

// Comparison function for qsort on doubles
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

// Helper function to sleep for specified milliseconds
static void sleep_ms(uint64_t ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep(ms * 1000);
#endif
}

// Read the CPU timestamp counter (RDTSC instruction)
uint64_t read_rdtsc(void) {
#ifdef _WIN32
    return __rdtsc();
#else
    return __rdtsc();
#endif
}

// Measure actual sleep time in milliseconds
uint64_t measure_sleep_ms(uint64_t requested_ms) {
    uint64_t start = get_time_ms();
    sleep_ms(requested_ms);
    uint64_t end = get_time_ms();
    return end - start;
}

// Measure RDTSC delta over a given sleep period
uint64_t measure_rdtsc_delta(uint64_t sleep_ms_val) {
    uint64_t start = read_rdtsc();
    sleep_ms(sleep_ms_val);
    uint64_t end = read_rdtsc();
    return end - start;
}

// Measure time to execute a loop of N operations
double measure_loop_ms(uint64_t num_operations) {
    volatile uint64_t dummy = 0;
    uint64_t start = get_time_ms();

    // Perform simple arithmetic operations in a loop
    for (uint64_t i = 0; i < num_operations; i++) {
        dummy += i;
    }

    uint64_t end = get_time_ms();
    return (double)(end - start);
}

// Calculate operations per millisecond for a loop
uint64_t measure_ops_per_ms(uint64_t num_operations) {
    double time_ms = measure_loop_ms(num_operations);

    // Avoid division by zero
    if (time_ms < 0.001) {
        time_ms = 0.001;
    }

    return (uint64_t)(num_operations / time_ms);
}

// Run the multi-sample loop jitter test
void measure_loop_stats(struct loop_stats *out,
                        int n_samples,
                        uint64_t ops_per_sample) {
    if (!out || n_samples <= 0) return;

    double *buf = (double *)malloc(sizeof(double) * (size_t)n_samples);
    if (!buf) return;

    for (int i = 0; i < n_samples; i++) {
        volatile uint64_t dummy = 0;
        double t0 = get_time_precise_ms();
        for (uint64_t j = 0; j < ops_per_sample; j++) {
            dummy += j;
        }
        double t1 = get_time_precise_ms();
        buf[i] = t1 - t0;
    }

    qsort(buf, (size_t)n_samples, sizeof(double), cmp_double);

    out->samples   = n_samples;
    out->min_ms    = buf[0];
    out->max_ms    = buf[n_samples - 1];
    out->median_ms = buf[n_samples / 2];

    // 95th percentile (index = ceil(0.95 * n) - 1, clamped)
    int p95_idx = (int)(0.95 * n_samples);
    if (p95_idx >= n_samples) p95_idx = n_samples - 1;
    out->p95_ms = buf[p95_idx];

    out->passed = (out->median_ms <= LOOP_JITTER_MEDIAN_THRESH &&
                   out->p95_ms    <= LOOP_JITTER_P95_THRESH) ? 1 : 0;

    free(buf);
}

// Collect all timing measurements into a result structure
void collect_timing_measurements(struct timing_result *result,
                                 uint64_t sleep_ms,
                                 uint64_t loop_ops) {
    if (!result) {
        return;
    }

    // Measure actual sleep time
    result->sleep_ms_actual = measure_sleep_ms(sleep_ms);

    // Measure RDTSC delta
    result->rdtsc_delta = measure_rdtsc_delta(sleep_ms);

    // Measure loop time (legacy single-shot, kept for ops_per_ms)
    result->loop_ms = measure_loop_ms(loop_ops);

    // Calculate operations per millisecond (legacy)
    result->ops_per_ms = measure_ops_per_ms(loop_ops);

    // Multi-sample loop jitter test (replaces single-shot for pass/fail)
    measure_loop_stats(&result->loop,
                       LOOP_JITTER_SAMPLES,
                       LOOP_JITTER_OPS_PER_SAMPLE);

    // Backwards compatibility: set loop_ms to the statistical median
    result->loop_ms = result->loop.median_ms;
}
