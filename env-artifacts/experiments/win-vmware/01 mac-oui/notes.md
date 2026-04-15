## 01 - MAC OUI Evasion

Date: 2026-01-31

Baseline:
- MAC vendor: VMware
- MAC check: FAILED

Change:
- Manually set MAC to XEROX CORPORATION OUI via VMware settings, achieved this by generating random OUI from hellion.org.uk

Expected:
- MAC check → PASSED

Result:
- MAC check → PASSED
- Other checks unchanged

Side Effects:
- No network issues observed
