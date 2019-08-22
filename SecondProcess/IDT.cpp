#include "IDT.h"

PULONG GetKiProcessorBlock()
{
	PULONG KiProcessorBlock = 0;

	//使当前线程运行在第一个处理器上（只有第一个处理器的kpcr才有KiProcessorBlock的值）
	KeSetSystemAffinityThread(1);

	__asm {
		push	eax

		mov		eax, fs:[0x34]
		add		eax,20h
		mov		eax,[eax]
		mov		eax,[eax]
		mov		eax,[eax+218h]
		mov		[KiProcessorBlock], eax

		pop		eax
	}

	KeRevertToUserAffinityThread();

	return KiProcessorBlock;
}

VOID SetIDTEntry(ULONG position, ULONG addr)
{
	USHORT tmp = 0;
	UCHAR idtDescriptor[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0xEE, 0x00, 0x00};

	__asm {
		push	eax
		mov		eax, addr
		mov		tmp, ax
		pop		eax
	}

	*(PUSHORT)&idtDescriptor[0] = tmp;

	__asm {
		push	eax
		mov		eax, addr
		shr		eax, 0x10
		mov		tmp, ax
		pop		eax
	}

	*(PUSHORT)&idtDescriptor[6] = tmp;

	//----------------------------------------------------------
	PULONG KiProcessorBlock = GetKiProcessorBlock();
	if (NULL == KiProcessorBlock)
	{
		DbgPrint("%s(%d): GetKiProcessorBlock failed. \n", __FILE__, __LINE__);
		return;
	}

	ULONG index = 0;
	ULONG idtAddr = 0;   

	while(KiProcessorBlock[index]) {
		idtAddr = KiProcessorBlock[index] - 0x120 + 0x38;
		idtAddr = (*(PULONG)idtAddr) + position * 8;

		PageProtectOff();

		*(PULONG)idtAddr = *(PULONG)&idtDescriptor[0];
		*((PULONG)idtAddr + 1) = *(PULONG)&idtDescriptor[4];

		PageProtectOn();
		
		DbgPrint("修改IDT表: CPUIndex:%d IDTADDR:%08X \n", index, idtAddr);
		
		index++;
	}
}