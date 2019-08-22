#ifndef __KERNEL_H_
#define __KERNEL_H_

#include <ntddk.h>

#include "SSDT.h"

extern PKSYSTEM_SERVICE_TABLE pSystemServiceTable;

/*
	这个函数只能写裸函数，否则结果不可控（非裸函数，自动生成的汇编可能会把eax清0）

	执行后的堆栈图：
	esp->	|__返回地址__|
			|___参数N____|
			|倒数第二参数|
			|最后一个参数|
	执行前的堆栈图：
	esp->	|__返回地址__|
			|trap_frame头部|
*/
VOID __declspec(naked) YKiSystemCall()
{
	__asm {
		mov		ecx, eax					//ecx = eax = 3环传入的函数编号

		shl		eax, 2						//eax << 2 = eax * 4

		mov		esi, [pSystemServiceTable]	//esi = pSystemServiceTable
		mov		esi, [esi]					//esi = *pSystemServiceTable

		add		eax, esi					//eax = 0环函数的地址的地址
		mov		eax, [eax]					//eax = 0环函数的地址

		mov		esi, [pSystemServiceTable]	//esi = pSystemServiceTable
		mov		esi, [esi + 0x0C]			//esi = 存放函数参数的表的地址

		add		esi, ecx					//ecx = 0环函数的参数字节数的地址

		xor		ecx, ecx
		mov		cl, [esi]					//ecx = 0环函数参数字节数

		mov		esi, [esp + 0x04 + 0x60]	//ebp = trap_frame（esp + 返回地址占的4字节） + 0x60, esi = ebp3
		add		esi, 0x08					//| ebp | 返回地址 | 第一个参数 | ……
		
		sub		esp, ecx
		mov		edi, esp
		
		shr		ecx, 2						//ecx = 参数个数
							
		rep		movsd						//将参数拷贝到0环堆栈

		call	eax
		
		ret
	}
}

VOID _declspec(naked) YKiSystemService()
{
	__asm {
		push    0
		push    ebp
		push    ebx
		push    esi
		push    edi
		push    fs

		mov     ebx, 30h
		mov     fs, bx
		mov     ebx, 23h
		mov     ds, bx
		mov     es, bx
		
		mov     esi, fs:124h
		
		push    dword ptr fs:[0]
		mov     dword ptr fs:[0], 0FFFFFFFFh
		
		push    dword ptr[esi + 13Ah]
		
		sub     esp, 48h
		
		mov     ebx, [esp + 6ch]
		and     ebx, 1
		mov		[esi + 13Ah], bl
		
		mov     ebp, esp
		
		mov     ebx, [esi + 128h]
		mov		[ebp + 3Ch], ebx
		and     dword ptr[ebp + 2Ch], 0
		mov		[esi + 128h], ebp

		cld
		mov     ebx, [ebp+60h]
		mov     edi, [ebp+68h]
		mov     [ebp+0Ch], edx
		mov     dword ptr [ebp+8], 0BADB0D00h
		mov     [ebp+0], ebx
		mov     [ebp+4], edi
		sti

		call	YKiSystemCall

//恢复寄存器，为回3环做准备
recoverRegister:
		add		esp, 0x50

		pop		fs
		pop		edi
		pop		esi
		pop		ebx
		pop		ebp

		add		esp, 0x04	//跳过ErrCode

//返回3环
returnR3:
		iretd
	}
}

#endif
