#ifndef __FEATURE_CODE_H_
#define __FEATURE_CODE_H_

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

	/*
		某段内存中出现特征码的次数

		baseAddr		搜索的内存起始位置
		baseAddrSize	搜索的范围
		featureCode		特征码数组（必须是连续的）
		featureCodeSize	特征码大小
	*/
	ULONG FC_AppareFeatureCodeTimes(ULONG baseAddr, ULONG baseAddrSize, PUCHAR featureCode, ULONG featureCodeSize);

	/*
		使用特征码在某段内存中找数据（函数、变量）地址

		baseAddr		搜索的内存起始位置
		baseAddrSize	搜索的范围
		featureCode		特征码数组（必须是连续的）
		featureCodeSize	特征码大小
		distance		特征码第一个字节离要找的地址的距离
		isBefore		特征码第一个字节是否在要找的地址的前面 1是 0否
	*/
	ULONG FC_FindDataAddr(ULONG baseAddr, ULONG baseAddrSize, UCHAR* featureCode, ULONG featureCodeSize, ULONG distance, ULONG isBefore);


#ifdef __cplusplus
}
#endif

#endif
