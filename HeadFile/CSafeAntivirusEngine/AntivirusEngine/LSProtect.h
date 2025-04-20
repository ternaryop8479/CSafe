/*
 * LSProtect.h
 * CSafe杀毒引擎子引擎LSProtect的DLL加载&封装API(LSProtect为基于PE文件导入表的启发式引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef LSProtect_PACK_H
#define LSProtect_PACK_H

#include "EngineHeadFile/DLLFunction.h"

char detectLSProtectDLL() {
	toDLLFunction dllLSProtect("LSProtect.dll", "LSProtect");
	return 0;
}

static const char LSProtectDetectLoader = detectLSProtectDLL();//利用变量的初始化实现在主函数执行之前执行该函数

std::string LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	static toDLLFunction dllLSProtect("LSProtect.dll", "LSProtect");
	typedef std::string (*funcLSProtect)(std::string, bool);
	funcLSProtect functionLSProtect = (funcLSProtect)dllLSProtect.getFuntion();
	return functionLSProtect(TargetPath, EnableSensitiveMode);
}

#endif