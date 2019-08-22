#include "common.h"

/*
	关闭页保护
*/
void PageProtectOff()
{
	__asm {
		cli
		mov		eax, cr0
		and		eax, not 0x10000
		mov		cr0, eax
	}
}

/*
	恢复内存保护
*/
void PageProtectOn()
{
	__asm {
		mov		eax, cr0
		or		eax, 0x10000
		mov		cr0, eax
		sti
	}
}

/*
	一次性修改8字节内存
*/
VOID Hook8b(IN ULONG hookAddr, IN PUCHAR hookBytesArr, OUT PUCHAR oldCode)
{
	ULONG lowData = *(PULONG)&hookBytesArr[0];
	ULONG highData = *(PULONG)&hookBytesArr[4];

	if(NULL != oldCode) {
		RtlMoveMemory(oldCode, (PVOID)hookAddr, 8);
	}

	PageProtectOff();

	__asm {
		mov		ebx, [lowData]
		mov		ecx, [highData]

		mov		edi, [hookAddr]

		cmpxchg8b qword ptr ds:[edi]
		lock cmpxchg8b qword ptr ds:[edi]
	}

	PageProtectOn();
}
