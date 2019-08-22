#include "hook_kfunction.h"

/************************************************************************/
/*
	hook、unhook内核函数NtOpenProcess
*/
/************************************************************************/
static ULONG NtOpenProcessRetAddr;

VOID Run_NtOpenProcess(IN ULONG pid, IN ULONG cr3Val)
{
	PEPROCESS process = (PEPROCESS)GetProcessByPid(pid);
	if (0 == process)
	{
		return;
	}

	PSTR processName = GetImageFileName(process);
	if (NULL == processName)
	{
		return;
	}

	DbgPrint("【%s( %d )】 open 【%s (%d)】 \n", GetCurrentImageFileName(), PsGetCurrentProcessId(), processName, pid);

	//如果eprocess.DirectoryTableBase != cr3，将cr3写入，cr3一定是真实的页目录表基址
	if (cr3Val != GetCurrentProcessDirectoryTableBase())
	{
		SetCurrentProcessDirectoryTableBase(cr3Val);
	}
}

VOID __declspec(naked) Dispatch_NtOpenProcess()
{
	if (IsDNF())
	{
		__asm {
			mov		eax, cr3
			push	eax
			mov		eax, [esp + 0x14]
			push	[eax]
			call	Run_NtOpenProcess
		}
	}
	
	__asm {
	RetFun:
		mov     edi, edi
		push    ebp
		mov     ebp, esp

		jmp		NtOpenProcessRetAddr
	}
}

NTSTATUS Hook_NtOpenProcess()
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("Hook_NtOpenProcess \n");
	return status;

	UCHAR hookBytes[8] = { 0xe9, 0x00, 0x00, 0x00, 0x00, 0x51, 0x51, 0x64 };

	ULONG funAddr = KF_GetNtOpenProcessAddr();
	if (0 == funAddr)
	{
		alert("Hook_NtOpenProcess: KF_GetNtOpenProcessAddr=0");

		return STATUS_UNSUCCESSFUL;
	}

	ULONG hookAddr = funAddr;

	NtOpenProcessRetAddr = hookAddr + 5;

	*(PULONG)(hookBytes + 1) = (ULONG)Dispatch_NtOpenProcess - hookAddr - 5;

	Hook8b(hookAddr, hookBytes, NULL);

	operate_prompt("Hook_NtOpenProcess");

	return status;
}

NTSTATUS UnHook_NtOpenProcess()
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("UnHook_NtOpenProcess \n");
	return status;

	UCHAR hookBytes[8] = { 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x51, 0x64 };

	ULONG funAddr = KF_GetNtOpenProcessAddr();
	if (0 == funAddr)
	{
		alert("UnHook_NtOpenProcess: KF_GetNtOpenProcessAddr=0");

		return STATUS_UNSUCCESSFUL;
	}

	ULONG hookAddr = funAddr;

	NtOpenProcessRetAddr = 0;

	Hook8b(hookAddr, hookBytes, NULL);

	operate_prompt("UnHook_NtOpenProcess");

	return status;
}