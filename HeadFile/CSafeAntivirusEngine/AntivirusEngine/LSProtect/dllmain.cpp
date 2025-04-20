/*
 * BITProtect/dllmain.cpp
 * CSafe杀毒引擎子引擎LSProtect的API封装及定义(LSProtect为基于导入表的启发引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "LSProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport std::string LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	return _LSProtect(TargetPath, EnableSensitiveMode);
}