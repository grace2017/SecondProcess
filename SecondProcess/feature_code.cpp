#include "feature_code.h"

/*
	某段内存中出现特征码的次数

	baseAddr		搜索的内存起始位置
	baseAddrSize	搜索的范围
	featureCode		特征码数组（必须是连续的）
	featureCodeSize	特征码大小
*/
ULONG FC_AppareFeatureCodeTimes(ULONG baseAddr, ULONG baseAddrSize, PUCHAR featureCode, ULONG featureCodeSize)
{
	PUCHAR pBaseAddr = NULL;
	ULONG times = 0;

	ULONG i = 0;
	ULONG j = 0;

	pBaseAddr = (PUCHAR)baseAddr;

	for (; i < baseAddrSize; i++) {
		if (pBaseAddr[i] == featureCode[0]) {
			for (j = 1; j < featureCodeSize; j++) {
				if (pBaseAddr[i + j] != featureCode[j]) {
					break;
				}
			}

			if (j == featureCodeSize) times++;
		}
	}

	return times;
}

/*
	使用特征码在某段内存中找数据（函数、变量）地址

	baseAddr		搜索的内存起始位置
	baseAddrSize	搜索的范围
	featureCode		特征码数组（必须是连续的）
	featureCodeSize	特征码大小
	distance		特征码第一个字节离要找的地址的距离
	isBefore		特征码第一个字节是否在要找的地址的前面 1是 0否
*/
ULONG FC_FindDataAddr(ULONG baseAddr, ULONG baseAddrSize, UCHAR* featureCode, ULONG featureCodeSize, ULONG distance, ULONG isBefore)
{
	ULONG appareTimes = 0;

	PUCHAR pBaseAddr = NULL;

	ULONG i = 0;
	ULONG j = 0;

	//检测特征码在这块内存中出现的次数，不等于1执行结束
	if (1 != (appareTimes = FC_AppareFeatureCodeTimes(baseAddr, baseAddrSize, featureCode, featureCodeSize))) {
		DbgPrint("%s(%d): FeatureCode appare times: %d. \n", __FILE__, __LINE__, appareTimes);

		return 0;
	}

	pBaseAddr = (PUCHAR)baseAddr;

	for (; i < baseAddrSize; i++) {
		if (pBaseAddr[i] == featureCode[0]) {
			for (j = 1; j < featureCodeSize; j++) {
				if (pBaseAddr[i + j] != featureCode[j]) {
					break;
				}
			}

			if (j == featureCodeSize) {
				if (0 == isBefore) {
					return (ULONG)pBaseAddr + i - distance;
				}
				else {
					return (ULONG)pBaseAddr + i + distance;
				}
			}
		}
	}

	return 0;
}