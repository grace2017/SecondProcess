#ifndef __IDT_H_
#define __IDT_H_

#include <ntddk.h>

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

	PULONG GetKiProcessorBlock();

	VOID SetIDTEntry(ULONG position, ULONG addr);

#ifdef __cplusplus
}
#endif

#endif
