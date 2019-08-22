#include "kernelfun_rewrite.h"

NTSTATUS NTAPI NtDebugActiveProcess(IN HANDLE ProcessHandle, IN HANDLE DebugHandle)
{
	PEPROCESS Process, CurrentProcess;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PETHREAD LastThread;
	NTSTATUS Status;

	Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_SUSPEND_RESUME, *PsProcessType, PreviousMode, (PVOID *)&Process, NULL);
	if (!NT_SUCCESS(Status))
	{
		alert("NtDebugActiveProcess: 获取被调试进程的eprocess失败");

		return Status;
	}

	if ((PsGetCurrentProcess() == Process) || (PsInitialSystemProcess == Process))
	{
		alert("NtDebugActiveProcess: 当前进程或初始化系统进程");

		ObDereferenceObject(Process);

		return STATUS_ACCESS_DENIED;
	}

	CurrentProcess = PsGetCurrentProcess();
	if (PreviousMode == UserMode && (0 == *(PULONG)((ULONG)Process + 0x26c)) && (0 == *(PULONG)((ULONG)CurrentProcess + 0x26c)))
	{
		DbgPrint("ProtectedProcess#################### \n");

		ObfDereferenceObject(Process);

		return STATUS_PROCESS_IS_PROTECTED;
	}

	ULONG DbgkDebugObjectType = KF_GetDbgkDebugObjectTypeAddr();
	if (0 == DbgkDebugObjectType)
	{
		alert("NtDebugActiveProcess: DbgkDebugObjectType=0");

		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}
	
	Status = ObReferenceObjectByHandle(DebugHandle, DEBUG_OBJECT_ADD_REMOVE_PROCESS, *(POBJECT_TYPE *)DbgkDebugObjectType, PreviousMode, (PVOID *)&DebugObject, NULL);
	if (!NT_SUCCESS(Status))
	{
		alert("NtDebugActiveProcess: 获取调试对象地址失败");

		ObDereferenceObject(Process);

		return Status;
	}

//	MyDebugPortDLinkListAdd(g_pDebugPortDLinkList, (ULONG)Process, (ULONG)DebugObject, (ULONG)PsGetCurrentProcess());

//	DbgPrint("【加入链表】Process: %X, DebugObject:%X, DebuggerProcess: %X \n", Process, DebugObject, PsGetCurrentProcess());

	if (!ExAcquireRundownProtection((PEX_RUNDOWN_REF)((ULONG)Process + 0xb0)))
	{
		alert("NtDebugActiveProcess: ExAcquireRundownProtection failed");

		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);

		return STATUS_PROCESS_IS_TERMINATING;
	}

	//-----------------------------------------------------------------------------
	Type_DbgkpPostFakeProcessCreateMessages MyDbgkpPostFakeProcessCreateMessages = (Type_DbgkpPostFakeProcessCreateMessages)KF_GetDbgkpPostFakeProcessCreateMessagesAddr();
	if (0 == MyDbgkpPostFakeProcessCreateMessages)
	{
		alert("NtDebugActiveProcess: MyDbgkpPostFakeProcessCreateMessages failed");

		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);

		return STATUS_UNSUCCESSFUL;
	}

	Status = MyDbgkpPostFakeProcessCreateMessages(Process, DebugObject, &LastThread);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("NtDebugActiveProcess: MyDbgkpPostFakeProcessCreateMessages failed(errCode: %X) \n", Status);

		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);

		return STATUS_UNSUCCESSFUL;
	}
	
	//-------------------------------------------------------------------------------
	Type_DbgkpSetProcessDebugObject MyDbgkpSetProcessDebugObject = (Type_DbgkpSetProcessDebugObject)KF_GetDbgkpSetProcessDebugObjectAddr();
	if (0 == MyDbgkpSetProcessDebugObject)
	{
		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);

		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("%X | %X | %X | %X \n", Process, DebugObject, Status, LastThread);

	Status = MyDbgkpSetProcessDebugObject(Process, DebugObject, LastThread);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("NtDebugActiveProcess: DbgkpSetProcessDebugObject failed(errCode: %X) \n", Status);

		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);

		return STATUS_UNSUCCESSFUL;
	}

	//-------------------------------------------------------------------------------
	ExReleaseRundownProtection((PEX_RUNDOWN_REF)((ULONG)Process + 0xb0));

	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);

	return Status;
}

/*
	通过切cr3实现读取其他进程内存
*/
NTSTATUS NTAPI NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID buff = NULL;
	ULONG currentCr3 = 0;
	ULONG otherCr3 = 0;
	PEPROCESS process;

	if (NULL == ProcessHandle || (NULL == BaseAddress) || (NULL == Buffer) || (0 == NumberOfBytesToRead))
	{
		DbgPrint("NtReadVirtualMemory: params error \n");
		return STATUS_UNSUCCESSFUL;
	}

	//----------
	buff = ExAllocatePool(NonPagedPool, NumberOfBytesToRead);
	if (NULL == buff)
	{
		DbgPrint("NtReadVirtualMemory: ExAllocatePool failed \n");

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(buff, NumberOfBytesToRead);

	//----------
	currentCr3 = GetCurrentProcessCR3();

	//----------
	Status = ObReferenceObjectByHandle(ProcessHandle, 0x10, *PsProcessType, KernelMode, (PVOID *)&process, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("NtReadVirtualMemory: ObReferenceObjectByHandle failed(errCode: 0x%X) \n", Status);
		return Status;
	}

	//----------
	otherCr3 = GetProcessDirectoryTableBase(process);
	if (0 == otherCr3)
	{
		DbgPrint("NtReadVirtualMemory: GetProcessDirectoryTableBase failed(result: 0) \n");

		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}

	//----------将其他进程的内存读入内核空间刚申请的内存中
	SetCurrentProcessCR3(otherCr3);

	RtlCopyMemory(buff, BaseAddress, NumberOfBytesToRead);

	SetCurrentProcessCR3(currentCr3);

	//----------
	RtlCopyMemory(Buffer, buff, NumberOfBytesToRead);

	//----------
	ExFreePool(buff);
	ObDereferenceObject(process);

	return Status;
}

NTSTATUS NTAPI NtReadVirtualMemory1(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID buff = NULL;
	PEPROCESS process;
	KAPC_STATE ApcState;
DbgPrint("NtReadVirtualMemory1 \n");
	if (NULL == ProcessHandle || (NULL == BaseAddress) || (NULL == Buffer) || (0 == NumberOfBytesToRead))
	{
		DbgPrint("NtReadVirtualMemory: params error \n");
		return STATUS_UNSUCCESSFUL;
	}

	//----------
	buff = ExAllocatePool(NonPagedPool, NumberOfBytesToRead);
	if (NULL == buff)
	{
		DbgPrint("NtReadVirtualMemory: ExAllocatePool failed \n");

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(buff, NumberOfBytesToRead);

	//----------
	Status = ObReferenceObjectByHandle(ProcessHandle, 0x10, *PsProcessType, KernelMode, (PVOID *)&process, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("NtReadVirtualMemory: ObReferenceObjectByHandle failed(errCode: 0x%X) \n", Status);
		return Status;
	}
DbgPrint("before KeStackAttachProcess \n");
	//----------
	Type_KeStackAttachProcess KeStackAttachProcess = (Type_KeStackAttachProcess)KF_GetKeStackAttachProcessAddr();
	KeStackAttachProcess((PKPROCESS)process, &ApcState);
DbgPrint("after KeStackAttachProcess \n");
	//----------
	RtlCopyMemory(buff, BaseAddress, NumberOfBytesToRead);

	//----------
	Type_KeUnstackDetachProcess KeUnstackDetachProcess = (Type_KeUnstackDetachProcess)KF_GetKeUnstackDetachProcessAddr();
	KeUnstackDetachProcess(&ApcState);
	
	//----------
	RtlCopyMemory(Buffer, buff, NumberOfBytesToRead);

	//----------
	ExFreePool(buff);
	ObDereferenceObject(process);

	return Status;
}

NTSTATUS NTAPI MyNtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *UnsafeBaseAddress,
	IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG UnsafeOldAccessProtection
	)
{
	NTSTATUS	Status = STATUS_SUCCESS;
	PEPROCESS	CurrentProcess = PsGetCurrentProcess();
	PEPROCESS	Process = NULL;
	KAPC_STATE	ApcState;
	ULONG		OldAccessProtection = 0;
	SIZE_T		NumberOfBytesToProtect = 0;
	PVOID		BaseAddress = 0;

	__try
	{
		BaseAddress = *UnsafeBaseAddress;
		NumberOfBytesToProtect = *UnsafeNumberOfBytesToProtect;
	}
	__except (1)
	{
		return STATUS_INVALID_PARAMETER;
	}

	Type_MiProtectVirtualMemory MiProtectVirtualMemory = (Type_MiProtectVirtualMemory)KF_GetMiProtectVirtualMemoryAddr();
	if (0 == MiProtectVirtualMemory)
	{
		DbgPrint("MyNtProtectVirtualMemory: MiProtectVirtualMemory=0 \n");
		return STATUS_UNSUCCESSFUL;
	}

	Status = ObReferenceObjectByHandle(ProcessHandle, 0x08, *PsProcessType, KernelMode, (PVOID *)&Process, NULL);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//----------
	Type_KeStackAttachProcess KeStackAttachProcess = (Type_KeStackAttachProcess)KF_GetKeStackAttachProcessAddr();
	Type_KeUnstackDetachProcess KeUnstackDetachProcess = (Type_KeUnstackDetachProcess)KF_GetKeUnstackDetachProcessAddr();

	if (Process != CurrentProcess)
	{
		KeStackAttachProcess((PKPROCESS)Process, &ApcState);
	}

operate_prompt("Call MyNtProtectVirtualMemory");

	Status = MiProtectVirtualMemory(Process, &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, &OldAccessProtection);

	if (Process != CurrentProcess)
	{
		KeUnstackDetachProcess(&ApcState);
	}

	ObDereferenceObject(Process);

	__try
	{
		*UnsafeOldAccessProtection = OldAccessProtection;
		*UnsafeBaseAddress = BaseAddress;
		*UnsafeNumberOfBytesToProtect = NumberOfBytesToProtect;
	}
	__except (1)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return Status;
}