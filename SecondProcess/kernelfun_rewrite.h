#ifndef __KERNELFUN_REWRITE_H_
#define __KERNELFUN_REWRITE_H_

#include <ntddk.h>
#include "common.h"
#include "kernel_function.h"
#include "debugport.h"
#include "process.h"

#ifdef __cplusplus
	extern "C" {
#endif
		extern PMyDebugPortDLinkList g_pDebugPortDLinkList;


		NTSTATUS NTAPI NtDebugActiveProcess(IN HANDLE ProcessHandle, IN HANDLE DebugHandle);

		NTSTATUS NTAPI NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead OPTIONAL);
		NTSTATUS NTAPI NtReadVirtualMemory1(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead OPTIONAL);

		NTSTATUS NTAPI MyNtProtectVirtualMemory(
			IN HANDLE ProcessHandle,
			IN OUT PVOID *UnsafeBaseAddress,
			IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG UnsafeOldAccessProtection
		);

#ifdef __cplusplus
	}
#endif

#endif
