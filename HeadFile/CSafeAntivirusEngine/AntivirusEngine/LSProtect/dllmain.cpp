/*
 * BITProtect/dllmain.cpp
 * CSafeɱ������������LSProtect��API��װ������(LSProtectΪ���ڵ�������������)
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "LSProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport std::string LSProtect(const std::string TargetPath, const bool EnableSensitiveMode = false) {
	return _LSProtect(TargetPath, EnableSensitiveMode);
}