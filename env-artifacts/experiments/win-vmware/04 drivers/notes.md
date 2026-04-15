05 - Driver Artefact Evasion Experiment

Evaluate whether VMware/Hyper-V kernel drivers can be disabled or removed to evade detection.

## Baseline
Detector output showed:
- vm3dmp*
- vmci
- Hyper-V related drivers
Driver check: FAILED

## Mitigation Attempt
Actions performed:
- Disabled vm3dmp service via sc config
- Attempted sc stop
- Rebooted system
- Uninstalled VMware Tools (where applicable)

## Results
- driverquery still lists VMware and Hyper-V drivers
- Detector still reports FAILED
- Drivers appear to be PnP / kernel-level and reload on boot

## Conclusion
Kernel-level driver artefacts are resilient to guest-level modification.
Disabling services is insufficient to evade detection.
Driver artefacts represent high-confidence virtualisation indicators.