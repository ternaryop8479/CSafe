/*
 * WhiteProtect/dllmain.cpp
 * CSafe杀毒引擎白启发引擎WhiteProtect的DLL导出函数主函数
 * Made By Ternary_Operator
 * Copyright (c) 2024 Ternary_Operator
*/

#include "WhiteProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport WPCODE WhiteProtect(const std::string TargetPath, const double SensitiveValue = 1.0) {
	return _WhiteProtect(TargetPath, SensitiveValue);
}