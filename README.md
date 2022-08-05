# bypass vmp vm detect

This tool is aimed to bypass vmp vmware detect (Tested vmp3.6)

vmp check virtual machine through 2 ways

- use `cpuid` instruction check
- check firmware table from the firmware table provider



## bypass cpuid check

edit vmware `.vmx` file,add the following code

```code
hypervisor.cpuid.v0 = "FALSE"
```



## bypass firmware table check

install vmp_vm_detect driver

