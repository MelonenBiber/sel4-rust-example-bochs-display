# Adapted from seL4/configs/X64_verified.cmake

# Unchanged
set(KernelPlatform "pc99" CACHE STRING "")
set(KernelSel4Arch "x86_64" CACHE STRING "")
set(KernelMaxNumNodes "1" CACHE STRING "")
set(KernelOptimisation "-O2" CACHE STRING "")
set(KernelRetypeFanOutLimit "256" CACHE STRING "")
set(KernelBenchmarks "none" CACHE STRING "")
set(KernelDangerousCodeInjection OFF CACHE BOOL "")
set(KernelFastpath ON CACHE BOOL "")
set(KernelNumDomains 16 CACHE STRING "")
set(KernelRootCNodeSizeBits 19 CACHE STRING "")
set(KernelFSGSBase "inst" CACHE STRING "")

# Changed
set(KernelVerificationBuild OFF CACHE BOOL "") # No printing with a verified config
set(KernelPrinting ON CACHE BOOL "") # Kernel debug printing: shows errors in stdout and enables the seL4_DebugPutChar syscall which println!() relies on currently
set(KernelMaxNumBootinfoUntypedCaps 240 CACHE STRING "")

# Added
set(KernelSupportPCID OFF CACHE BOOL "") # My cpu does not support the pcid feature, you may be able to remove this
