#ifndef __SSDT_H_
#define __SSDT_H_

#include <ntddk.h>

typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;          // 函数地址表基地址
	PULONG  ServiceCounterTableBase;   // SSDT函数被调用的次数
	ULONG   NumberOfService;           // 函数的个数
	PUSHORT  ParamTableBase;           // 函数参数表基地址
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;  // ntoskrnl.exe 的函数
	KSYSTEM_SERVICE_TABLE   win32k;    // win32k.sys 的函数
	KSYSTEM_SERVICE_TABLE   notUsed1;
	KSYSTEM_SERVICE_TABLE   notUsed2;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

#ifdef __cplusplus
extern "C" {
#endif

	/*
		创建SSDT表
	*/
	NTSTATUS CreateSystemServiceTable(PKSYSTEM_SERVICE_TABLE* returnVal);

	/*
		释放SSDT表
	*/
	VOID FreeSystemServiceTable(PKSYSTEM_SERVICE_TABLE pSystemServiceTable);

	/*
		向SSDT表中加入函数
	*/
	NTSTATUS AddFun2SystemServiceTable(PKSYSTEM_SERVICE_TABLE pSystemServiceTable, ULONG funAddr, UCHAR paramNumber);

#ifdef __cplusplus
}
#endif

#endif
