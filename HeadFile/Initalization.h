/*
 * Initalization.h
 * 包含CSafe杀毒软件的初始化部分
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

bool quietMode = false; // global

#include <tchar.h>
#include <direct.h>
#include "AntivirusSoftHeadFile/Log.h"
#include "AntivirusSoftHeadFile/Else.h"
#include "AntivirusSoftHeadFile/Authority.h"
#include "AntivirusSoftHeadFile/MBR.h"
#include "AntivirusSoftHeadFile/SharedMap.h"
#include "MainAntivirus.h"
#include "MainUI.h"

void DisableCloseButton() {
	HWND hWnd = GetConsoleWindow(); // 获取控制台窗口句柄
	HMENU hMenu = GetSystemMenu(hWnd, FALSE); // 获取系统菜单句柄

	if (hMenu != NULL) {
		EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED); // 禁用关闭菜单项
	}
}