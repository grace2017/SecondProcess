#ifndef __HOOK_DBGFUNCTION_H_
#define __HOOK_DBGFUNCTION_H_

#include <ntddk.h>
#include "common.h"
#include "debugport.h"
#include "kernel_function.h"
#include "process.h"
#include "kernelfun_rewrite.h"

#ifdef __cplusplus
extern "C" {
#endif
	extern PMyDebugPortDLinkList g_pDebugPortDLinkList;

	/*
		debugport清0
	*/
	NTSTATUS Hook_NtDebugActiveProcess();
	NTSTATUS UnHook_NtDebugActiveProcess();

	/*
		跳转值至重写的NtDebugActiveProcess
	*/
	NTSTATUS Hook_NtDebugActiveProcess_rewrite();
	NTSTATUS UnHook_NtDebugActiveProcess_rewrite();

	/*
		讲调试进程的eprocess、被调试进程的eprocess、调试对象存放到双向链表中
	*/
	NTSTATUS Hook_DbgkpSetProcessDebugObject();
	NTSTATUS UnHook_DbgkpSetProcessDebugObject();

	/*
		修改取debugport值逻辑
	*/
	NTSTATUS Hook_DbgkpQueueMessage();
	NTSTATUS UnHook_DbgkpQueueMessage();


	NTSTATUS Hook_KiDispatchException();
	NTSTATUS UnHook_KiDispatchException();

	NTSTATUS Hook_DbgkForwardException();
	NTSTATUS UnHook_DbgkForwardException();


	NTSTATUS Hook_PspExitThread();
	NTSTATUS UnHook_PspExitThread();

	NTSTATUS Hook_DbgkExitThread();
	NTSTATUS UnHook_DbgkExitThread();

	NTSTATUS Hook_DbgkCreateThread();
	NTSTATUS UnHook_DbgkCreateThread();


	NTSTATUS Hook_DbgkExitProcess();
	NTSTATUS UnHook_DbgkExitProcess();


	NTSTATUS Hook_NtWaitForDebugEvent();
	NTSTATUS UnHook_NtWaitForDebugEvent();

	NTSTATUS Hook_NtQueryObject();
	NTSTATUS UnHook_NtQueryObject();

	NTSTATUS Hook_NtCreateDebugObject();
	NTSTATUS UnHook_NtCreateDebugObject();

	NTSTATUS Hook_NtDebugContinue();
	NTSTATUS UnHook_NtDebugContinue();

	NTSTATUS Hook_DbgkpMarkProcessPeb();
	NTSTATUS UnHook_DbgkpMarkProcessPeb();

	NTSTATUS Hook_DbgkMapViewOfSection();
	NTSTATUS UnHook_DbgkMapViewOfSection();

	NTSTATUS Hook_DbgkUnMapViewOfSection();
	NTSTATUS UnHook_DbgkUnMapViewOfSection();

	NTSTATUS Hook_NtQueryInformationProcess();
	NTSTATUS UnHook_NtQueryInformationProcess();

	NTSTATUS Hook_NtQueryInformationThread();
	NTSTATUS UnHook_NtQueryInformationThread();

	NTSTATUS Recover_NtAllocateVirtualMemory();
	NTSTATUS Recover_KiAttachProcess();
	NTSTATUS Recover_KeResumeThread();
	NTSTATUS Recover_SeDefaultObjectMethod();
	NTSTATUS Recover_KiSwapThread();
	NTSTATUS Recover_ZwFsControlFile();
	NTSTATUS Recover_PsResumeProcess();

#ifdef __cplusplus
}
#endif

#endif
