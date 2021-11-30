# NtRays
NtRays is a Hex-Rays microcode plugin for automated simplification of Windows Kernel decompilation.


## Features
- Cleanup of instrumentation and scheduler hinting code.

  ![](https://i.can.ac/zPTAq.png)
  
- Lifting of dynamic relocations for page tables and PFN database with LA57 support.

  ![](https://i.can.ac/mKFfB.png)
  
- RSB flush lifting in ISRs.

  ![](https://i.can.ac/YW5AQ.png)

## Planned Features
- ETHREAD/EPROCESS where KTHREAD/KPROCESS is used. 

## Installation
Simply drop the NtRays64.dll into the plugins folder.
Note: IDA 7.4+ is required.

## License
NtRays is licensed under BSD-3-Clause License.
