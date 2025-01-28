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

- Lifting of SYSCALL instructions with the ability to select Nt* signatures.

## How to compile

### Windows with Visual Studio 2022

Place a copy of idasdk90 in the root directory of NtRays as well as in the build folder.

```
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 .. -DIDA_SDK_DIR=idasdk90 -DHEXRAYS_SDK_DIR=idasdk90
cmake --build . --config Release
```

### Linux
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DIDA_SDK_DIR=idasdk90 -DHEXRAYS_SDK_DIR=/root/idapro-9.0/plugins/hexrays_sdk/
make
```

### macOS
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DIDA_SDK_DIR=./idasdk90 -DHEXRAYS_SDK_DIR=./idasdk90
make
```

## Installation
Simply drop the NtRays64.dll into the plugins folder.
Note: IDA 7.6+ is required.

## License
NtRays is licensed under BSD-3-Clause License.
