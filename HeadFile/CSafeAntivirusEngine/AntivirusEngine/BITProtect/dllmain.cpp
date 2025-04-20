/*
 * BITProtect/dllmain.cpp
 * CSafe杀毒引擎子引擎BITProtect的API封装及定义(BITProtect为基于PE文件函数特征的启发式引擎)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "BITProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport std::string BITProtect(const std::string TargetPath, const float BlackWeight = 1.0, const float WhiteWeight = 1.0) {
	return _BITProtect(TargetPath, BlackWeight, WhiteWeight);
}