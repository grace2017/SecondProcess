#include "kernel_object.h"

/*
	打印内核结构相关信息

	打印内核对象名也可以这样
	DbgPrint("DriverName=%wZ \n", pDriverObj->DriverName);
*/
VOID PrintKernelObject(IN PDRIVER_OBJECT pDriverObj)
{
	if (NULL == pDriverObj)
	{
		alert("IkPrintKernelObject: pDriverObj=NULL");

		return;
	}

	DbgPrint("ObjectAddr=%p \n", pDriverObj);
	DbgPrint("DriverStart=%p \n", pDriverObj->DriverStart);
	DbgPrint("DriverSize=%p \n", pDriverObj->DriverSize);
	DbgPrint("DriverName=%S \n", pDriverObj->DriverName.Buffer);
}

/*
	通过内核结构体中的双向链表遍历内核结构体
*/
VOID EnumKernelObject1()
{
	PLDR_ENTRY pHeader = NULL;
	PLDR_ENTRY pCurrent = NULL;

	pHeader = (PLDR_ENTRY)g_pDriverObj->DriverSection;
	pCurrent = (PLDR_ENTRY)pHeader->InLoadOrderLinks.Flink;

	while (pHeader != pCurrent) {
		if ((0 != pCurrent->DllBase) && (0 != pCurrent->EntryPoint) && (0 != pCurrent->SizeOfImage)) {
			if (0 == pCurrent->BaseDllName.Length)
			{
				DbgPrint("内核对象名称被抹去 \n");
			} 
			else
			{
				//DbgPrint("%wZ \n", pCurrent->BaseDllName) 这样输出不行，原因未知
				DbgPrint("%S \n", pCurrent->BaseDllName.Buffer);
			}
		}

		pCurrent = (PLDR_ENTRY)pCurrent->InLoadOrderLinks.Flink;
	}
}

/*
	获取内核对象的相关信息
*/
PLDR_ENTRY GetKernelObjectEntry(IN PWSTR kernelObjName)
{
	PLDR_ENTRY pHeader = NULL;
	PLDR_ENTRY pCurrent = NULL;

	UNICODE_STRING searchObjName = { 0 };
	RtlInitUnicodeString(&searchObjName, kernelObjName);

	pHeader = (PLDR_ENTRY)g_pDriverObj->DriverSection;
	pCurrent = (PLDR_ENTRY)pHeader->InLoadOrderLinks.Flink;

	while (pHeader != pCurrent) {
		if ((0 != pCurrent->DllBase) && (0 != pCurrent->EntryPoint) && (0 != pCurrent->SizeOfImage)) {
			if (0 == pCurrent->BaseDllName.Length)
			{
				alert("内核对象名称被抹去");

				return NULL;
			}
			else
			{
				if (0 == RtlCompareUnicodeString(&pCurrent->BaseDllName, &searchObjName, FALSE)) {
					return pCurrent;
				}
			}
		}

		pCurrent = (PLDR_ENTRY)pCurrent->InLoadOrderLinks.Flink;
	}

	return NULL;
}