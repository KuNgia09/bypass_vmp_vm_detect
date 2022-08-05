# Bypass Vmp vm detect



## What it does

This tool is aimed to bypass Vmp vmware detection (Tested on Vmp3.6), it patches `SystemFirmwareTable` at runtime, it removes all detectable signatures like **"VMware" "Virtual" "VMWARE"**.





## Vmp check vm mechanism

Vmp check virtual machine in 2 ways

- use `cpuid` instruction check
- check firmware table from the firmware table provider



## Bypass cpuid check

Edit vmware `.vmx` file,add the following code

```code
hypervisor.cpuid.v0 = "FALSE"
```





## Build

Visual Studio 2019 and WDK 10

## Bypass firmware table check

Install our driver to patch `SystemFirmwareTable`



## Thanks

[https://github.com/hzqst/VmwareHardenedLoader](https://github.com/hzqst/VmwareHardenedLoader)

[Zydis](https://github.com/zyantific/zydis.git)
