# NtRays
NtRays is a Hex-Rays microcode plugin for automated simplification of Windows Kernel decompilation.


## Features
- Cleanup of instrumentation and scheduler hinting code.

  ![](https://i.can.ac/zPTAq.png)

- Lifting of multiple missing instructions.

  ![](https://i.can.ac/BKL9G.png)
  
- Lifting of TrapFrame accesses and interrupt/syscall returns.

  ![](https://i.can.ac/5h6wU.png)
  
- Inference of KUSER_SHARED_DATA segments.

  ![](https://i.can.ac/SGIp2.png)
  
- Lifting of dynamic relocations for page tables and PFN database with LA57 support.

  ![](https://i.can.ac/LxA48.png)
  
- RSB flush lifting in ISRs.

  ![](https://i.can.ac/YW5AQ.png)
  
- Replacement of KTHREAD/KPROCESS with ETHREAD/EPROCESS in user types, local variables and arguments.

## Installation
Simply drop the NtRays64.dll into the plugins folder.
Note: IDA 7.6+ is required.

## License
NtRays is licensed under BSD-3-Clause License.
