VMX Hardening – CPUID Suppression

Configuration:
- hypervisor.cpuid.v0 = "FALSE"

Results:
- CPUID hypervisor bit → PASSED
- VMware backdoor → PASSED (not detected)
- BIOS, drivers, registry, filesystem still FAILED
- Suspicion score: 12 (threshold: 6)

Conclusion:
CPU-level hypervisor signature successfully suppressed.
Firmware and driver artefacts remain detectable.