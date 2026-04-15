#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>

// Tunable constants for the multi-sample loop jitter test
#define LOOP_JITTER_SAMPLES      50
#define LOOP_JITTER_OPS_PER_SAMPLE 2000000  // 2M ops per sample
#define LOOP_JITTER_MEDIAN_THRESH  8.0     // ms
#define LOOP_JITTER_P95_THRESH     12.0     // ms

// Statistics from the multi-sample loop jitter test
struct loop_stats {
    int    samples;
    double median_ms;
    double p95_ms;
    double min_ms;
    double max_ms;
    int    passed;   // 1 = passed, 0 = failed
};

// Structure to hold timing measurements
struct timing_result {
    uint64_t sleep_ms_actual;      // Actual time slept in milliseconds
    uint64_t rdtsc_delta;          // CPU timestamp counter delta
    double loop_ms;                // Backwards compat: set to median_ms
    uint64_t ops_per_ms;           // Operations per millisecond (legacy)
    struct loop_stats loop;        // Multi-sample loop jitter stats
};

// Measure actual sleep time in milliseconds
// Sleeps for requested_ms and returns actual time elapsed
uint64_t measure_sleep_ms(uint64_t requested_ms);

// Read the CPU timestamp counter (RDTSC instruction)
uint64_t read_rdtsc(void);

// Measure RDTSC delta over a given sleep period
// Returns the difference in TSC values
uint64_t measure_rdtsc_delta(uint64_t sleep_ms);

// Measure time to execute a loop of N operations
// Returns time in milliseconds
double measure_loop_ms(uint64_t num_operations);

// Calculate operations per millisecond for a loop
uint64_t measure_ops_per_ms(uint64_t num_operations);

// Run the multi-sample loop jitter test and populate loop_stats
void measure_loop_stats(struct loop_stats *out,
                        int n_samples,
                        uint64_t ops_per_sample);

// Collect all timing measurements into a result structure
void collect_timing_measurements(struct timing_result *result,
                                 uint64_t sleep_ms,
                                 uint64_t loop_ops);

#endif // TIMING_H
