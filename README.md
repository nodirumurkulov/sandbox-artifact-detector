# Final Year Project

A Windows-first defensive research tool for detecting virtualisation and sandbox artefacts that malware may use to identify analysis environments.
This project was developed as a Final Year Project and focuses on measuring how visible a sandboxed or virtualised environment is, then supporting controlled hardening through reporting, scoring, and remediation features.

## Main Features
- BIOS and firmware string detection
- MAC OUI detection
- virtualisation driver and service detection
- registry and filesystem artefact checks
- timing-based checks
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
- `PASSED` = no obvious artefact detected
- `FAILED` = artefact detected
- `ERROR` = unsupported or unavailable check

## Platform Focus
The main implementation and evaluation are focused on:
- Windows guest environments
- VMware-based testing
Some parts of the codebase are portable, but the full feature set is Windows-first.

## Build
### Windows
```cmd
cd C:\PROJECT\env-artifacts
  mkdir build
  cd build
  cmake ..
  cmake --build . --config Debug
  cmake --build . --config Release
  .\build\Debug\detector.exe
  .\build\Debug\detector.exe -- verbose (shows failure with reasons)
```

### macOS / Linux
```bash
cd C:\PROJECT\env-artifacts
 mkdir build
 cd build
 cmake ..
 make -j8
 ./detector
```

Logs
Each run produces:
- console output for immediate review
- a timestamped JSON report in logs/

Project Structure
src/       implementation
include/   headers
build/     generated build output
logs/      generated JSON reports

Limitations
- research prototype, not a production security tool
- primary implementation target is Windows
- evaluation is mainly VMware-focused
- some hardening features may affect VM usability

Responsible Use
This tool is intended for defensive research and authorised sandbox assessment only.