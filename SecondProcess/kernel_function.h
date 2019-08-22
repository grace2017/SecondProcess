#ifndef __KERNEL_FUNCTION_H_
#define __KERNEL_FUNCTION_H_

#include <ntddk.h>
#include "feature_code.h"
#include "kernel_object.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

	/*
		定义函数原型指针
	*/
	typedef ULONG (* Type_ObGetObjectType)(IN PVOID object);
	typedef NTSTATUS (NTAPI *Type_DbgkpPostFakeProcessCreateMessages)(IN PEPROCESS Process, IN PDEBUG_OBJECT DebugObject, OUT PETHREAD *LastThread);
	typedef NTSTATUS(NTAPI *Type_DbgkpSetProcessDebugObject)(IN PEPROCESS Process, IN PDEBUG_OBJECT DebugObject, IN PETHREAD LastThread);

	typedef VOID (NTAPI *Type_KeStackAttachProcess)(IN PKPROCESS Process, OUT PRKAPC_STATE ApcState);
	typedef VOID(NTAPI *Type_KeUnstackDetachProcess)(IN PRKAPC_STATE ApcState);

	typedef NTSTATUS (NTAPI *Type_NtProtectVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN OUT PVOID *UnsafeBaseAddress,
		IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
		IN ULONG NewAccessProtection,
		OUT PULONG UnsafeOldAccessProtection
	);

	typedef NTSTATUS (NTAPI *Type_MiProtectVirtualMemory)(
		IN PEPROCESS Process,
		IN OUT PVOID *BaseAddress,
		IN OUT PSIZE_T NumberOfBytesToProtect,
		IN ULONG NewAccessProtection,
		OUT PULONG OldAccessProtection OPTIONAL
	);

	/*
		获取函数地址
	*/
	ULONG KF_GetObGetObjectTypeAddr();

	ULONG KF_GetDbgkpSetProcessDebugObjectAddr();

	ULONG KF_GetNtDebugActiveProcessAddr();
	ULONG KF_GetDbgkDebugObjectTypeAddr();

	ULONG KF_GetNtWaitForDebugEventAddr();

	ULONG KF_GetDbgkpQueueMessageAddr();

	ULONG KF_GetKiDispatchExceptionAddr();

	ULONG KF_GetDbgkForwardExceptionAddr();

	ULONG KF_GetDbgkCreateThreadAddr();
	ULONG KF_GetDbgkExitThreadAddr();
	ULONG KF_GetPspExitThreadAddr();

	ULONG KF_GetPspCreateProcessAddr();
	ULONG KF_GetNtTerminateProcessAddr();
	ULONG KF_GetPspTerminateProcessAddr();
	ULONG KF_GetDbgkExitProcessAddr();

	ULONG KF_GetDbgkpPostFakeProcessCreateMessagesAddr();

	ULONG KF_GetNtQueryObjectAddr();

	ULONG KF_GetNtCreateDebugObjectAddr();

	ULONG KF_GetNtDebugContinueAddr();

	ULONG KF_GetDbgkpMarkProcessPebAddr();

	ULONG KF_GetNtQueryInformationProcessAddr();
	ULONG KF_GetNtQueryInformationThreadAddr();
	ULONG KF_GetNtQuerySystemInformationAddr();

	ULONG KF_GetDbgkpPostFakeThreadMessagesAddr();
	ULONG KF_GetDbgkpPostModuleMessagesAddr();

	ULONG KF_GetKeStackAttachProcessAddr();
	ULONG KF_GetKeUnstackDetachProcessAddr();

	ULONG KF_GetKeInitializeProcessAddr();

	ULONG KF_GetNtAllocateVirtualMemoryAddr();
	ULONG KF_GetKiAttachProcessAddr();
	ULONG KF_GetKeResumeThreadAddr();
	ULONG KF_GetSeDefaultObjectMethodAddr();
	ULONG KF_GetKiSwapThreadAddr();
	ULONG KF_GetZwFsControlFileAddr();
	ULONG KF_GetPsResumeProcessAddr();

	ULONG KF_GetNtOpenProcessAddr();

	ULONG KF_GetDbgkMapViewOfSectionAddr();
	ULONG KF_GetDbgkUnMapViewOfSectionAddr();

	/*
		内存相关
	*/
	ULONG KF_GetMiProtectVirtualMemoryAddr();
	ULONG KF_GetNtProtectVirtualMemoryAddr();

#ifdef __cplusplus
}
#endif

#endif
