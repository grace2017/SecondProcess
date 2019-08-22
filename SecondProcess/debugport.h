#ifndef __DEBUGPORT_H_
#define __DEBUGPORT_H_

#include <ntddk.h>
#include "common.h"

typedef struct _MyDebugPort
{
	ULONG		process;		//被调试进程eprocess的地址
	ULONG		debuggerProcess;//调试器进程eprocess的地址
	ULONG		debugObject;

	struct _MyDebugPort		*prev;
	struct _MyDebugPort		*next;
}MyDebugPort, *PMyDebugPort;

typedef struct _MyDebugPortDLinkList
{
	PMyDebugPort	top;
	PMyDebugPort	bottom;
	int				eleNum;
}MyDebugPortDLinkList, *PMyDebugPortDLinkList;

#ifdef __cplusplus
extern "C" {
#endif
	PMyDebugPort createMyDebugPort(IN ULONG process, IN ULONG debugObject, IN ULONG debuggerProcess);

	PMyDebugPortDLinkList MyDebugPortDLinkListCreate();
	BOOLEAN MyDebugPortDLinkListIsEmpty(IN PMyDebugPortDLinkList pDLinkList);
	VOID MyDebugPortDLinkListFree(IN PMyDebugPortDLinkList pDLinkList);
	VOID MyDebugPortDLinkListTraverseTop(IN PMyDebugPortDLinkList pDlinkList);
	ULONG MyDebugPortDLinkListFind(IN PMyDebugPortDLinkList pDLinkList, IN ULONG process);
	ULONG MyDebugPortDLinkListFindByDebuggerProcess(IN PMyDebugPortDLinkList pDLinkList, IN ULONG debuggerProcess);
	BOOLEAN MyDebugPortDLinkListDelete(IN PMyDebugPortDLinkList pDLinkList, IN ULONG process);
	BOOLEAN MyDebugPortDLinkListAdd(IN PMyDebugPortDLinkList pDLinkList, IN ULONG process, IN ULONG debugObject, IN ULONG debuggerProcess);


#ifdef __cplusplus
}
#endif

#endif
