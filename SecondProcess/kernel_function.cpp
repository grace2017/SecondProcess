#include "kernel_function.h"

static PVOID s_GetKernelFunctionAddr(PWSTR funName)
{
	UNICODE_STRING usFunction;
	RtlInitUnicodeString(&usFunction, funName);

	return MmGetSystemRoutineAddress(&usFunction);
}

ULONG KF_GetObGetObjectTypeAddr()
{
	UCHAR code[] = { 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x0f, 0xb6, 0x40, 0xf4, 0x8b, 0x04, 0x85 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetObGetObjectTypeAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0, 0);
}

ULONG KF_GetDbgkpSetProcessDebugObjectAddr()
{
	UCHAR code[] = { 0x7d, 0x09, 0x89, 0x4d, 0x10, 0x89, 0x44, 0x24, 0x10, 0xeb, 0x04};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpSetProcessDebugObjectAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 11, 0x33, 0);
}

ULONG KF_GetNtDebugActiveProcessAddr()
{
	UCHAR code[] = { 0x0f, 0x84, 0xd1, 0x00, 0x00, 0x00, 0x80, 0xfb, 0x01, 0x75, 0x2d, 0x64, 0xa1, 0x24, 0x01, 0x00, 0x00};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtDebugActiveProcessAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 17, 0x57, 0);
}

ULONG KF_GetDbgkDebugObjectTypeAddr()
{
	ULONG addr = KF_GetNtDebugActiveProcessAddr();
	if (0 == addr)
	{
		alert("KF_GetDbgkDebugObjectTypeAddr: KF_GetNtDebugActiveProcessAddr=0");

		return 0;
	}

	return *(PULONG)(addr + 0x9a);
}

ULONG KF_GetNtWaitForDebugEventAddr()
{
	UCHAR code[] = { 0x8b, 0x7d, 0x10, 0x3b, 0xfb, 0x74, 0x30, 0x84, 0xc0, 0x74, 0x12, 0x8b, 0xcf };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtWaitForDebugEventAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 13, 0x4b, 0);
}

ULONG KF_GetDbgkpQueueMessageAddr()
{
	UCHAR code[] = { 0x75, 0x0a, 0xb8, 0x9a, 0x00, 0x00, 0xc0, 0xe9, 0x6e, 0x02, 0x00, 0x00};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpQueueMessageAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 12, 0x34, 0);
}

ULONG KF_GetKiDispatchExceptionAddr()
{
	UCHAR code[] = { 0x0f, 0x85, 0x15, 0x01, 0x00, 0x00, 0x80, 0x3d, 0x80, 0x02, 0xdf, 0xff, 0x01, 0x75, 0x49, 0x83, 0x7b, 0x14, 0x08 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKiDispatchExceptionAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 19, 0xf7, 0);
}

ULONG KF_GetDbgkForwardExceptionAddr()
{
	UCHAR code[] = { 0x75, 0x0d, 0x80, 0x7d, 0x0c, 0x01, 0x75, 0x07, 0x32, 0xc0, 0xe9, 0x81, 0x00, 0x00, 0x00};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkForwardExceptionAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x67, 0);
}

ULONG KF_GetDbgkCreateThreadAddr()
{
	UCHAR code[] = { 0x0f, 0x84, 0xde, 0x01, 0x00, 0x00, 0x8d, 0x7d, 0xb0, 0x89, 0x7d, 0xcc, 0x89, 0x5d, 0xb0 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkCreateThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x46, 0);
}

ULONG KF_GetDbgkExitThreadAddr()
{
	UCHAR code[] = { 0x74, 0x2f, 0xa8, 0x02, 0x74, 0x2b, 0x8b, 0x45, 0x08, 0x89, 0x44, 0x24, 0x20, 0x8d, 0x04, 0x24 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkExitThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 16, 0x2f, 0);
}

ULONG KF_GetPspExitThreadAddr()
{
	UCHAR code[] = { 0x8d, 0x8b, 0x70, 0x02, 0x00, 0x00, 0x33, 0xd2, 0x42, 0x8b, 0xf1, 0x33, 0xc0, 0xf0, 0x0f, 0xb1, 0x16, 0x85, 0xc0, 0x74, 0x0a, 0x83, 0xf8, 0x01, 0x74, 0x05 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetPspExitThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 26, 0x6c, 0);
}

ULONG KF_GetPspCreateProcessAddr()
{
	UCHAR code[] = { 0x74, 0x0a, 0xb8, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xc2, 0x01, 0x00, 0x00, 0x8b, 0x56, 0x50 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetPspCreateProcessAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x4f, 0);
}

ULONG KF_GetNtTerminateProcessAddr();
ULONG KF_GetPspTerminateProcessAddr();

ULONG KF_GetDbgkExitProcessAddr()
{
	UCHAR code[] = { 0x74, 0x3a, 0xa8, 0x02, 0x74, 0x36, 0x81, 0xc1, 0xa8, 0x00, 0x00, 0x00, 0x51, 0xe8, 0xce, 0x22, 0xd8, 0xff };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkExitProcessAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 18, 0x2f, 0);
}

ULONG KF_GetDbgkpPostFakeProcessCreateMessagesAddr()
{
	UCHAR code[] = { 0xff, 0x75, 0x0c, 0x33, 0xc9, 0xff, 0x75, 0x08, 0xe8, 0x4e, 0xfb, 0xff, 0xff, 0x85, 0xc0 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpPostFakeProcessCreateMessagesAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x15, 0);
}

ULONG KF_GetNtQueryObjectAddr()
{
	UCHAR code[] = { 0x74, 0x5a, 0x89, 0x5d, 0xfc, 0x8b, 0x7d, 0x10, 0x83, 0x7d, 0x0c, 0x04, 0x74, 0x04, 0x6a, 0x04 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtQueryObjectAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x2e, 0);
}

ULONG KF_GetNtCreateDebugObjectAddr()
{
	UCHAR code[] = { 0x85, 0x45, 0x14, 0x74, 0x0a, 0xb8, 0x0d, 0x00, 0x00, 0xc0, 0xe9, 0xb7, 0x00, 0x00, 0x00 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtCreateDebugObjectAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x40, 0);
}

ULONG KF_GetNtDebugContinueAddr()
{
	UCHAR code[] = { 0x3d, 0x01, 0x00, 0x01, 0x80, 0x74, 0x26, 0x3d, 0x00, 0x00, 0x01, 0x00, 0x7e, 0x15 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtDebugContinueAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 14, 0x4b, 0);
}

ULONG KF_GetDbgkpMarkProcessPebAddr()
{
	UCHAR code[] = { 0x84, 0xc0, 0x0f, 0x84, 0xed, 0x00, 0x00, 0x00, 0x83, 0xbf, 0xa8, 0x01, 0x00, 0x00, 0x00 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpMarkProcessPebAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x30, 0);
}

ULONG KF_GetNtQueryInformationProcessAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"NtQueryInformationProcess");
}

ULONG KF_GetNtQueryInformationThreadAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"NtQueryInformationThread");
}

ULONG KF_GetNtQuerySystemInformationAddr()
{
	UCHAR code[] = { 0x77 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtQuerySystemInformationAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 14, 0x50, 0);
}

ULONG KF_GetDbgkpPostFakeThreadMessagesAddr()
{
	UCHAR code[] = { 0x0f, 0x84, 0x72, 0x01, 0x00, 0x00, 0x85, 0xf6, 0x74, 0x07, 0x8b, 0xce };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpPostFakeThreadMessagesAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 12, 0x4c, 0);
}

ULONG KF_GetDbgkpPostModuleMessagesAddr()
{
	UCHAR code[] = { 0x89, 0x75, 0xe4, 0x3b, 0x5d, 0xdc, 0x0f, 0x84, 0x44, 0x01, 0x00, 0x00, 0x8b, 0x45, 0xe4 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetDbgkpPostModuleMessagesAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x3a, 0);
}

ULONG KF_GetKeStackAttachProcessAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"KeStackAttachProcess");
}

ULONG KF_GetKeUnstackDetachProcessAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"KeUnstackDetachProcess");
}

ULONG KF_GetKeInitializeProcessAddr()
{
	UCHAR code[] = { 0x41, 0x66, 0x3b, 0x4d, 0xdc, 0x73, 0x1a, 0xeb, 0xed, 0xeb, 0x16, 0x33, 0xc0, 0x8d, 0x7d, 0xf0 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKeInitializeProcessAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x54, 0);
}

ULONG KF_GetNtAllocateVirtualMemoryAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"NtAllocateVirtualMemory");
}

ULONG KF_GetKiAttachProcessAddr()
{
	UCHAR code[] = { 0x75, 0x13, 0x89, 0x86, 0x68, 0x01, 0x00, 0x00, 0x89, 0xbe, 0x6c, 0x01, 0x00, 0x00};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKiAttachProcessAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 14, 0x3d, 0);
}

ULONG KF_GetKeResumeThreadAddr()
{
	UCHAR code[] = { 0x75, 0x4c, 0x83, 0xbe, 0x40, 0x01, 0x00, 0x00, 0x00, 0x75, 0x43, 0x33, 0xf6, 0xeb, 0x22 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKeResumeThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x76, 0);
}

ULONG KF_GetSeDefaultObjectMethodAddr()
{
	UCHAR code[] = { 0xc2, 0x56, 0x74, 0x54, 0x48, 0x74, 0x3e, 0x48, 0x74, 0x20, 0x48, 0x74, 0x10, 0x52, 0x52, 0x68, 0x0d, 0x00, 0x00, 0xc0 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetSeDefaultObjectMethodAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 20, 0x0b, 0);
}

ULONG KF_GetKiSwapThreadAddr()
{
	UCHAR code[] = { 0xeb, 0x02, 0xf3, 0x90, 0x8b, 0x03, 0x85, 0xc0, 0x75, 0xde, 0x33, 0xc0, 0x8b, 0xcb, 0x40, 0x87, 0x01, 0x85, 0xc0, 0x75, 0xd3, 0x50, 0x8b, 0xc6};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKiSwapThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 24, 0xc3, 0);
}

ULONG KF_GetZwFsControlFileAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"ZwFsControlFile");
}

ULONG KF_GetPsResumeProcessAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"PsResumeProcess");
}

ULONG KF_GetNtOpenProcessAddr()
{
	return (ULONG)s_GetKernelFunctionAddr(L"NtOpenProcess");
}

ULONG KF_GetDbgkMapViewOfSectionAddr()
{
	UCHAR code[] = { 0x0f, 0x84, 0x1d, 0x01, 0x00, 0x00, 0x64, 0x8b, 0x15, 0x24, 0x01, 0x00, 0x00};

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKiSwapThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 13, 0x21, 0);
}

ULONG KF_GetDbgkUnMapViewOfSectionAddr()
{
	UCHAR code[] = { 0x0f, 0x84, 0x9a, 0x00, 0x00, 0x00, 0x64, 0x8b, 0x15, 0x24, 0x01, 0x00, 0x00, 0xf6, 0x82, 0x80, 0x02, 0x00, 0x00, 0x04 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetKiSwapThreadAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 20, 0x19, 0);
}

/************************************************************************/
/*
	ÄÚ´æÏà¹Ø
*/
/************************************************************************/
ULONG KF_GetMiProtectVirtualMemoryAddr()
{
	UCHAR code[] = { 0x83, 0xf8, 0xff, 0x75, 0x0a, 0xb8, 0x45, 0x00, 0x00, 0xc0, 0xe9, 0x9f, 0x04, 0x00, 0x00 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtProtectVirtualMemoryAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x38, 0);
}

ULONG KF_GetNtProtectVirtualMemoryAddr()
{
	UCHAR code[] = { 0x83, 0xf8, 0xff, 0x75, 0x0a, 0xb8, 0x45, 0x00, 0x00, 0xc0, 0xe9, 0x51, 0x01, 0x00, 0x00 };

	PLDR_ENTRY pEntry = GetKernelObjectEntry(L"ntoskrnl.exe");
	if (NULL == pEntry)
	{
		alert("KF_GetNtProtectVirtualMemoryAddr: GetKernelObjectEntry=NULL");

		return 0;
	}

	return FC_FindDataAddr(pEntry->DllBase, pEntry->SizeOfImage, code, 15, 0x14, 0);
}











