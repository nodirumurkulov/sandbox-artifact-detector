# Sandbox Artifact Detector

A defensive research tool for detecting virtualisation and sandbox artefacts that malware may use to identify analysis environments.

The project focuses on measuring how visible a virtualised analysis environment is and supporting controlled hardening through structured reporting, weighted scoring, remediation support, rollback, and before/after comparison. The current implementation is Windows-first and was evaluated mainly in VMware-based environments.

## Features

- BIOS and firmware string detection
- MAC OUI detection
- virtualisation driver and service detection
- registry artefact checks
- filesystem artefact checks
- timing-based checks
  - sleep acceleration
  - RDTSC timing
  - loop jitter
- CPUID hypervisor-bit detection
- VMware backdoor probe
- debugger-related checks
- console dashboard output
- timestamped JSON logging
- guest-side hardening support
- rollback support
- host-side patch generation
- before/after comparison support

## Output Convention

- `PASSED` = no obvious artefact detected by that check
- `FAILED` = artefact detected and the environment exposes a fingerprintable signal
- `ERROR` = the check is unsupported or could not be completed in the current environment

## Platform Scope

Primary implementation and evaluation focus:

- Windows guest environments
- VMware-based testing

Some parts of the codebase are portable, but the full feature set is Windows-first.

## Build

### Windows

From the repository root:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
.\build\Release\detector.exe
```

For a Debug build:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Debug
.\build\Debug\detector.exe
```

### macOS / Linux

```bash
cmake -S . -B build
cmake --build build -j
./build/detector
```

## Usage

Basic run:

```bash
detector
```

Typical Windows / VMware usage:

```bash
detector --platform vmware
```

Depending on the build and runtime environment, profile-based workflows may also be available:

```bash
detector --platform vmware --profile light
detector --platform vmware --profile moderate --auto-fix
detector --platform vmware --profile aggressive --auto-fix
```

## Logs

Each run produces:

- console output for immediate review
- a timestamped JSON report in `logs/`

These logs are intended for later analysis, comparison, and evidence capture.

## Project Structure

```text
src/       implementation
include/   headers
build/     generated build output
logs/      generated runtime reports
```

## Limitations

- research prototype, not a production security tool
- primary implementation target is Windows
- evaluation is mainly VMware-focused
- some hardening features may affect VM usability
- host-side patch generation provides guidance, not full automatic reconfiguration

## Responsible Use

This repository is intended for defensive research and authorised sandbox assessment only.
