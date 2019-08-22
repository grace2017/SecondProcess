#ifndef __KERNEL_OBJECT_H_
#define __KERNEL_OBJECT_H_

#include <ntddk.h>

#include "common.h"

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
}LDR_ENTRY, *PLDR_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif

	//不能放在extern "C" {}外
	extern PDRIVER_OBJECT g_pDriverObj;

	/*
		通过内核结构体中的双向链表遍历内核结构体
	*/
	VOID EnumKernelObject1();

	/*
		通过ZwQuerySystemInformation的第11号功能
	*/
	VOID EnumKernelObject2();

	/*
		打印内核结构相关信息
	*/
	VOID PrintKernelObject(IN PDRIVER_OBJECT pDriverObj);

	/*
		获取内核对象的相关信息
	*/
	PLDR_ENTRY GetKernelObjectEntry(IN PWSTR kernelObjName);


#ifdef __cplusplus
}
#endif

#endif
