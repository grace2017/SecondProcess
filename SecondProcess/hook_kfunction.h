#ifndef __HOOK_KFUNCTION_H_
#define __HOOK_KFUNCTION_H_

#include <ntddk.h>
#include "common.h"
#include "kernel_function.h"
#include "process.h"

#ifdef __cplusplus
extern "C" {
#endif

	NTSTATUS Hook_NtOpenProcess();
	NTSTATUS UnHook_NtOpenProcess();

#ifdef __cplusplus
}
#endif

#endif
