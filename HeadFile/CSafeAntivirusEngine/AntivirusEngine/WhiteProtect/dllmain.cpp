/*
 * WhiteProtect/dllmain.cpp
 * CSafeɱ���������������WhiteProtect��DLL��������������
 * Made By Ternary_Operator
 * Copyright (c) 2024 Ternary_Operator
*/

#include "WhiteProtect.h"
#define DLLExport __declspec(dllexport)

extern "C" DLLExport WPCODE WhiteProtect(const std::string TargetPath, const double SensitiveValue = 1.0) {
	return _WhiteProtect(TargetPath, SensitiveValue);
}