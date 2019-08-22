#include "SSDT.h"

/*
	创建SSDT表
*/
NTSTATUS CreateSystemServiceTable(PKSYSTEM_SERVICE_TABLE* returnVal)
{
	PVOID pFunAddrTable = NULL;
	PVOID pFunParamTable = NULL;
	PKSYSTEM_SERVICE_TABLE pSystemServiceTable = NULL;

	if (NULL == returnVal)
	{
		DbgPrint("%s(%d): 实参是空指针 \n", __FILE__, __LINE__);

		return STATUS_UNSUCCESSFUL;
	}

	pFunAddrTable = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 0);
	if (NULL == pFunAddrTable) {
		DbgPrint("%s(%d): ExAllocatePoolWithTag failed \n", __FILE__, __LINE__);

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pFunAddrTable, 0x1000);

	pFunParamTable = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 0);
	if (NULL == pFunParamTable) {
		DbgPrint("%s(%d): ExAllocatePoolWithTag failed \n", __FILE__, __LINE__);

		ExFreePoolWithTag(pFunAddrTable, 0);

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pFunParamTable, 0x1000);

	pSystemServiceTable = (PKSYSTEM_SERVICE_TABLE)ExAllocatePoolWithTag(NonPagedPool, sizeof(KSYSTEM_SERVICE_TABLE), 0);
	if (NULL == pSystemServiceTable) {
		DbgPrint("%s(%d): ExAllocatePoolWithTag failed \n", __FILE__, __LINE__);

		ExFreePoolWithTag(pFunAddrTable, 0);
		ExFreePoolWithTag(pFunParamTable, 0);

		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pSystemServiceTable, sizeof(KSYSTEM_SERVICE_TABLE));

	pSystemServiceTable->ServiceTableBase = (PULONG)pFunAddrTable;
	pSystemServiceTable->ParamTableBase = (PUSHORT)pFunParamTable;

	*returnVal = pSystemServiceTable;

	return STATUS_SUCCESS;
}

/*
	释放SSDT表
*/
VOID FreeSystemServiceTable(PKSYSTEM_SERVICE_TABLE pSystemServiceTable)
{
	if (NULL != pSystemServiceTable->ServiceTableBase) {
		ExFreePoolWithTag(pSystemServiceTable->ServiceTableBase, 0);
	}

	if (NULL != pSystemServiceTable->ParamTableBase) {
		ExFreePoolWithTag(pSystemServiceTable->ParamTableBase, 0);
	}

	if (NULL != pSystemServiceTable) {
		ExFreePoolWithTag(pSystemServiceTable, 0);
	}

	pSystemServiceTable = NULL;
}

/*
	向SSDT表中加入函数
*/
NTSTATUS AddFun2SystemServiceTable(PKSYSTEM_SERVICE_TABLE pSystemServiceTable, ULONG funAddr, UCHAR paramNumber)
{
	*(pSystemServiceTable->ServiceTableBase + pSystemServiceTable->NumberOfService) = funAddr;
	*(PUCHAR)((ULONG)pSystemServiceTable->ParamTableBase + pSystemServiceTable->NumberOfService) = paramNumber * 4;
	pSystemServiceTable->NumberOfService++;

	return STATUS_SUCCESS;
}