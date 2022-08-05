#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include"kernel_struct.h"
#include "Zydis/Zydis.h"




typedef struct
{
	PVOID base;
	size_t max_insts;
	int max_depth;
	
	

	PVOID lea_rcx_imm;
	PUCHAR lea_rcx_addr;
	PVOID pfn_ExAcquireResourceSharedLite;
	int call_ExAcquireResourceSharedLite_inst;
}LocateExpFirmwareTableContext;




PVOID g_NtosBase;
PVOID g_NtosEnd;
ULONG_PTR g_ExAcquireResourceSharedLite_address;
ULONG_PTR g_ExpFirmwareTableResource_address;
ULONG_PTR g_ExpFirmwareTableProviderListHead_address;
char patternCode[] = "\x41\xB8\x41\x52\x46\x54";

typedef NTSTATUS(__cdecl* PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);


PFNFTH g_OriginalACPIHandler = NULL;
PFNFTH g_OriginalRSMBHandler = NULL;
PFNFTH g_OriginalFIRMHandler = NULL;
ULONG_PTR g_diasmBranchList=0;
int g_diasmBranchIndex=0;

_Use_decl_annotations_ void* UtilGetSystemProcAddress(
	const wchar_t* proc_name) {
	PAGED_CODE();

	UNICODE_STRING proc_name_U = {};
	RtlInitUnicodeString(&proc_name_U, proc_name);
	return MmGetSystemRoutineAddress(&proc_name_U);
}


_Use_decl_annotations_ void* UtilMemMem(const void* search_base,
	SIZE_T search_size, const void* pattern,
	SIZE_T pattern_size) {
	if (pattern_size > search_size) {
		return nullptr;
	}
	auto base = static_cast<const char*>(search_base);
	for (SIZE_T i = 0; i <= search_size - pattern_size; i++) {
		if (RtlCompareMemory(pattern, &base[i], pattern_size) == pattern_size) {
			return const_cast<char*>(&base[i]);
		}
	}
	return nullptr;
}



VOID RemoveSigs(PVOID FirmwareBuffer, ULONG FirmwareBufferLength, const char* Sig, size_t SigLength)
{
	PUCHAR search_begin = (PUCHAR)FirmwareBuffer;
	SIZE_T search_size = FirmwareBufferLength;
	while (1)
	{
		auto find = UtilMemMem(search_begin, search_size, Sig, SigLength);
		if (!find)
			break;

		memset(find, '7', SigLength);
		search_begin = (PUCHAR)find + SigLength;
		search_size = (PUCHAR)FirmwareBuffer + FirmwareBufferLength - search_begin;
	}
}


NTSTATUS __cdecl  MyACPIHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo) {
	auto st = g_OriginalACPIHandler(SystemFirmwareTableInfo);

	if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
	{
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMWARE", sizeof("VMWARE") - 1);
	}
	return st;
}

NTSTATUS __cdecl  MyRSMBHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo) {
	auto st = g_OriginalACPIHandler(SystemFirmwareTableInfo);

	if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
	{
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMWARE", sizeof("VMWARE") - 1);
	}
	return st;
}

NTSTATUS __cdecl  MyFIRMHandler(PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo) {
	auto st = g_OriginalACPIHandler(SystemFirmwareTableInfo);

	if (st == STATUS_SUCCESS && SystemFirmwareTableInfo->Action == 1)
	{
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMware", sizeof("VMware") - 1);
		RemoveSigs(SystemFirmwareTableInfo->TableBuffer, SystemFirmwareTableInfo->TableBufferLength, "VMWARE", sizeof("VMWARE") - 1);
	}
	return st;
}


VOID
Print(
	_In_ PCCH Format,
	_In_ ...
)
{
	CHAR message[512];
	va_list argList;
	va_start(argList, Format);
	const int n = _vsnprintf_s(message, sizeof(message), sizeof(message) - 1, Format, argList);
	message[n] = '\0';
	vDbgPrintExWithPrefix("[ZYDIS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, argList);
	va_end(argList);
}






bool GetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID checkPtr)
{
	if (!g_NtosBase)
	{
		if (pMod->LoadOrderIndex == 0 || (checkPtr >= pMod->ImageBase &&
			checkPtr < (PVOID)((PUCHAR)pMod->ImageBase + pMod->ImageSize)))
		{
			g_NtosBase = pMod->ImageBase;
			g_NtosEnd = (PUCHAR)pMod->ImageBase + pMod->ImageSize;

			return true;
		}
	}

	return false;
}

NTSTATUS EnumSystemModules(fnEnumSystemModuleCallback callback, PVOID Context)
{
	ULONG cbBuffer = 0;
	PVOID pBuffer = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	while (1)
	{
		cbBuffer += 0x40000;
		pBuffer = ExAllocatePoolWithTag(PagedPool, cbBuffer, 'nmsl');

		if (pBuffer == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		Status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, cbBuffer, NULL);

		if (NT_SUCCESS(Status))
		{
			break;
		}

		ExFreePoolWithTag(pBuffer, 'nmsl');

		if (Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			return Status;
		}
	}

	if (pBuffer == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (NT_SUCCESS(Status))
	{
		auto pMods = (PRTL_PROCESS_MODULES)pBuffer;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			if (callback(&pMods->Modules[i], Context))
			{
				Status = STATUS_SUCCESS;
				break;
			}
		}
	}

	ExFreePoolWithTag(pBuffer, 'nmsl');

	return Status;
}

bool LocateExpFirmwareTableHandler(ULONG_PTR address, ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands) {
	UNREFERENCED_PARAMETER(address);
	UNREFERENCED_PARAMETER(instruction);
	UNREFERENCED_PARAMETER(operands);



	return true;
}


bool CheckSameBranch(ULONG_PTR address) {
	if (g_diasmBranchIndex >= 0x1000 / sizeof(ULONG_PTR)) {
		return true;
	}
	for (int i = 0; i < g_diasmBranchIndex; i++) {
		ULONG_PTR temp = *(ULONG_PTR*)(g_diasmBranchList + i * sizeof(ULONG_PTR));
		if (temp == address) {
			Print("Find same branch address:%p\n", address);
			return true;
		}
	}
	
	*(ULONG_PTR*)(g_diasmBranchList + g_diasmBranchIndex * sizeof(ULONG_PTR))=address;
	g_diasmBranchIndex++;
	return false;
}

NTSTATUS DiasmRangeWalk(ULONG_PTR diasmAddress,ULONG diasmSize,int depth) {
	// Initialize Zydis decoder and formatter
	ZydisDecoder decoder;
#ifdef _M_AMD64
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
#else
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32)))
#endif
		return STATUS_DRIVER_INTERNAL_ERROR;

	ZydisFormatter formatter;
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		return STATUS_DRIVER_INTERNAL_ERROR;

	NTSTATUS st=STATUS_SUCCESS;

	SIZE_T readOffset = 0;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
	ZyanStatus status;
	CHAR printBuffer[128];
	
	ULONG_PTR lea_rcx_imm=0;
	ULONG_PTR lea_rcx_address=0;
	ULONG_PTR calcAddress = 0;
	// Start the decode loop
	while ((status = ZydisDecoderDecodeFull(&decoder,
		(PVOID)(diasmAddress + readOffset), diasmSize - readOffset, &instruction,
		operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)) !=
		ZYDIS_STATUS_NO_MORE_DATA)
	{
		
		
		// Format and print the instruction
		const ZyanU64 runtime_address = (ZyanU64)(diasmAddress + readOffset);
		ZydisFormatterFormatInstruction(
			&formatter, &instruction, operands, instruction.operand_count_visible, printBuffer,
			sizeof(printBuffer), runtime_address);
		//Print("+%-4X 0x%-16llX\t\t%hs\n", (ULONG)readOffset, instrAddress, printBuffer);

		readOffset += instruction.length;
		if (readOffset > diasmSize) {
			return st;
		}

		if (g_ExpFirmwareTableProviderListHead_address) {
			return st;
		}


		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA && instruction.operand_count_visible == 2) {

			if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[0].reg.value == ZYDIS_REGISTER_RCX) {

				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[1], runtime_address, &calcAddress))){
					lea_rcx_address = runtime_address;
					lea_rcx_imm = calcAddress;
					Print("%p %s LEA imm value:%p\n", runtime_address, &printBuffer[0], lea_rcx_imm);
				}
				
			}



		}

		else if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.opcode == 0xE8 && instruction.operand_count_visible == 1) {
			//º∆À„PAGE:00000001404AF362 E8 A9 CC BC FF                                call    ExAcquireResourceSharedLite
			if (lea_rcx_address && (int)(runtime_address - lea_rcx_address) < 20) {
				if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0], runtime_address, &calcAddress))) {
						Print("%p  %s call calcAddress:%p\n", runtime_address, &printBuffer[0], calcAddress);
						if (calcAddress == g_ExAcquireResourceSharedLite_address) {
							g_ExpFirmwareTableResource_address = lea_rcx_imm;
							Print("g_ExpFirmwareTableResource_address :%p\n", g_ExpFirmwareTableResource_address);

						}
					}
					
				}

			}
		}
		//PAGE:0000000140619B66                mov     rcx, cs:ExpFirmwareTableProviderListHead
		//PAGE: 0000000140619B6D               add     rcx, 0FFFFFFFFFFFFFFE8h
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.opcode == 0x8B && instruction.operand_count_visible == 2) {
			if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && (operands->reg.value == ZYDIS_REGISTER_RCX || operands->reg.value == ZYDIS_REGISTER_RAX) && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].mem.base == ZYDIS_REGISTER_RIP) {
				
				Print("%p %s ,leax_rcx_address:%p",runtime_address,&printBuffer[0],lea_rcx_address);
				if (g_ExpFirmwareTableResource_address && lea_rcx_address && (int)(runtime_address-lea_rcx_address)<20) {
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[1], runtime_address, &calcAddress))){
							
						g_ExpFirmwareTableProviderListHead_address = calcAddress;
						Print("ExpFirmwareTableProviderListHead_address %p", g_ExpFirmwareTableProviderListHead_address);
						return st;
					}
				
				}
				
			}
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP || (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ)) {
			
			if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0], runtime_address, &calcAddress))) {
					Print("instruction %p:%s,Jcc imm:%p\n", runtime_address, &printBuffer[0],calcAddress);
					if (calcAddress >= (ULONG_PTR)g_NtosBase && calcAddress < (ULONG_PTR)g_NtosEnd) {
						if (!CheckSameBranch(calcAddress)) {
							
							int temp = depth + 1;
							Print("recurisve DiasmRangWalk at %p,depth£∫%d\n", calcAddress,temp);
							DiasmRangeWalk(calcAddress, 300, temp);
						}
						
							
					}
					
					
				}
				
			}

		}

		if (instruction.mnemonic == ZYDIS_MNEMONIC_RET ) {
			Print("instruction %p:%s\n", runtime_address, &printBuffer[0]);
			return st;
		}
		if (instruction.opcode == 0xcc) {
			Print("instruction %p:%s\n", runtime_address,&printBuffer[0]);
			return st;
		}

		
	}
	return st;
}

VOID SampleUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);
	
	PAGED_CODE();
	if (g_ExpFirmwareTableResource_address) {
		ExAcquireResourceExclusiveLite((PERESOURCE)g_ExpFirmwareTableResource_address, TRUE);

		PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE HandlerListCurrent = NULL;

		EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
			FirmwareTableProviderList,
			(PLIST_ENTRY)g_ExpFirmwareTableProviderListHead_address,
			HandlerListCurrent) {

			if (g_OriginalACPIHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'ACPI') {
				Print("ACPI found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalACPIHandler;
			}

			if (g_OriginalRSMBHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'RSMB') {
				Print("RSMB found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalRSMBHandler;
			}

			if (g_OriginalFIRMHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'FIRM') {
				Print("FIRM found, node restored!\n");
				HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = g_OriginalFIRMHandler;
			}
		}

		ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource_address);
	}

	if (g_diasmBranchList != NULL) {
		ExFreePoolWithTag((PVOID)g_diasmBranchList, '1gaT');
	}
	
	return;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = SampleUnload;
	KdPrint(("Sample driver initialized successfully\n"));

	PVOID checkPtr = UtilGetSystemProcAddress(L"NtOpenFile");

	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "DPFLTR_INFO_LEVEL\n"));


	Print("NtOpenFile address:%p\n", checkPtr);

	EnumSystemModules(GetKernelInfo, checkPtr);

	if (!g_NtosBase) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ntos base not found!\n");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		Print("ntos base:%p\n", g_NtosBase);
	}

	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(g_NtosBase);
	if (!NtHeader) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ntos ntheader not found!\n");
		return STATUS_UNSUCCESSFUL;
	}

	PIMAGE_SECTION_HEADER secheader = (PIMAGE_SECTION_HEADER)((PUCHAR)NtHeader + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);

	PUCHAR PAGEBase = NULL;
	SIZE_T PAGESize = 0;

	for (auto i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		//≤È’“PAGE sectionµÿ÷∑
		if (memcmp(secheader[i].Name, "PAGE\x0\x0\x0\x0", 8) == 0)
		{
			PAGEBase = (PUCHAR)g_NtosBase + secheader[i].VirtualAddress;
			PAGESize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
			break;
		}
	}

	if (!PAGEBase) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PAGE section not found!\n");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		Print("PAGE section address:%p\n", PAGEBase);
	}

	auto FindMovTag = UtilMemMem(PAGEBase, PAGESize, patternCode, sizeof(patternCode) - 1);

	if (!FindMovTag) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "mov r8d, 'TFRA' sig not found!\n");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		Print("mov r8d, 'TFRA' address:%p", FindMovTag);
	}
	g_diasmBranchList=(ULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, 0x1000, '1gaT');
	if (g_diasmBranchList == NULL) {
		Print("ExAllocatePoolWithTag failed");
	}

	
	g_ExAcquireResourceSharedLite_address = (ULONG_PTR)UtilGetSystemProcAddress(L"ExAcquireResourceSharedLite");
	
	Print("ExAcquireResourceSharedLite address:%p\n", g_ExAcquireResourceSharedLite_address);

	DiasmRangeWalk((ULONG_PTR)FindMovTag,300,0);
	if (g_ExpFirmwareTableResource_address == 0) {
		Print("ExpFirmwareTableResource_address not found");
		return STATUS_SUCCESS;
	}
	if (g_ExpFirmwareTableProviderListHead_address == 0) {
		Print("ExpFirmwareTableProviderListHead_address not found");
		return STATUS_SUCCESS;
	}
	ExAcquireResourceExclusiveLite((PERESOURCE)g_ExpFirmwareTableResource_address, TRUE);
	PSYSTEM_FIRMWARE_TABLE_HANDLER_NODE HandlerListCurrent = NULL;

	EX_FOR_EACH_IN_LIST(SYSTEM_FIRMWARE_TABLE_HANDLER_NODE,
		FirmwareTableProviderList,
		(PLIST_ENTRY)g_ExpFirmwareTableProviderListHead_address,
		HandlerListCurrent) {
		if (!g_OriginalACPIHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'ACPI') {
			Print("ACPI found, node manipulated!\n");
			g_OriginalACPIHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
			HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyACPIHandler;
		}

		if (!g_OriginalRSMBHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'RSMB') {
			Print("RSMB found, node manipulated!\n");
			g_OriginalRSMBHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
			HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyRSMBHandler;
		}

		if (!g_OriginalFIRMHandler && HandlerListCurrent->SystemFWHandler.ProviderSignature == 'FIRM') {
			Print("FIRM found, node manipulated!\n");
			g_OriginalFIRMHandler = HandlerListCurrent->SystemFWHandler.FirmwareTableHandler;
			HandlerListCurrent->SystemFWHandler.FirmwareTableHandler = MyFIRMHandler;
		}
	}
	ExReleaseResourceLite((PERESOURCE)g_ExpFirmwareTableResource_address);
	return STATUS_SUCCESS;
}