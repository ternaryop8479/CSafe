/*
 * BITProtect.h
 * CSafe杀毒引擎子引擎BITProtect的DLL加载&封装API(BITProtect为基于PE文件函数特征的启发式引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef BITProtect_PACK_H
#define BITProtect_PACK_H

#include "EngineHeadFile/DLLFunction.h"

char detectBITProtectDLL() {
	toDLLFunction dllBITProtect("BITProtect.dll", "BITProtect");
	return 0;
}

static const char BITProtectDetectLoader = detectBITProtectDLL();//利用变量的初始化实现在主函数执行之前执行该函数

std::string BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	static toDLLFunction dllBITProtect("BITProtect.dll", "BITProtect");
	typedef std::string (*funcBITProtect)(std::string, float, float);
	funcBITProtect functionBITProtect = (funcBITProtect)dllBITProtect.getFuntion();
	return functionBITProtect(TargetPath, BlackWeight, WhiteWeight);
}

#endif