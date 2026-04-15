06 – Timing Experiments (S7-timing-baseline)

Objective
Evaluate the stability of timing-based checks (Sleep, RDTSC, Loop Jitter) in a Windows 11 VMware VM under idle and CPU load conditions.

Setup
- Snapshot: `S7-timing-baseline` (restored from `S0-baseline-clean`)
- No VMX hardening or artefact evasion applied
- Detector executed from Release build


Baseline (Idle)

Structural artefacts (BIOS, MAC, drivers, registry, filesystem, CPUID) remained detectable.

Timing results (initial implementation):
- Sleep: PASSED
- RDTSC: PASSED
- Loop jitter: FAILED

Observation:  
The single-sample loop jitter implementation was overly sensitive to normal VM scheduling behaviour and produced false positives even at idle.


High CPU Load Test

Method:
Spawned 4 parallel PowerShell CPU stress jobs:
1..4 | % { Start-Job { while ($true) { [Math]::Sqrt(12345) } } } | Out-Null


Initial behaviour:
- Loop jitter remained FAILED
- Measured runtime increased under load

Conclusion (pre-refactor):  
Single-threshold loop jitter logic was too noisy to serve as a reliable binary classifier.


Refactored Statistical Loop Jitter

Replaced single-sample logic with:
- 50 samples
- Median and 95th percentile evaluation
- Tunable thresholds:
  - `median <= 8.0 ms`
  - `p95 <= 12.0 ms`

High CPU Load Results
- median_ms: 2.839
- p95_ms: 3.876
- max_ms: 4.024
- Status: PASSED

Conclusion:  
The statistical implementation is stable under CPU contention and significantly reduces false positives. Sleep and RDTSC checks remain stable.

Timing is treated as a supporting (low-weight) signal rather than a standalone classifier.