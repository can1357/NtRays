# NtRays
NtRays is a Hex-Rays microcode plugin for automated simplification of Windows Kernel decompilation.



## Features


- Cleanup of instrumentation and scheduler hinting code.

  <img src="https://i.can.ac/QOGGi.png" alt="Before" style="zoom:67%;" />

  <img src="https://i.can.ac/AlElF.png" alt="After"  />

- Lifting of dynamic relocations for page tables and PFN database with LA57 support.

  ![](https://i.can.ac/XC2X8.png)

  ![](https://i.can.ac/YrMJb.png)

- RSB flush lifting in ISRs.

  ![](https://i.can.ac/YW5AQ.png)

## Planned Features

- ETHREAD/EPROCESS where KTHREAD/KPROCESS is used. 

## License
NtRays is licensed under BSD-3-Clause License.
