/*
 * Initalization.h
 * ����CSafeɱ������ĳ�ʼ������
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
	HWND hWnd = GetConsoleWindow(); // ��ȡ����̨���ھ��
	HMENU hMenu = GetSystemMenu(hWnd, FALSE); // ��ȡϵͳ�˵����

	if (hMenu != NULL) {
		EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED); // ���ùرղ˵���
	}
}