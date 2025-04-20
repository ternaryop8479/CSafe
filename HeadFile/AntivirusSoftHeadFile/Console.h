/*
 * ProcessHandle.h
 * 包含杀毒软件用到的控制台函数
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <cstdio>
#include <Windows.h>

void GetCursorPosition(int *XAndY) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
		XAndY[0] = csbi.dwCursorPosition.X;
		XAndY[1] = csbi.dwCursorPosition.Y;
		return;
	}
	XAndY[0] = -1;
	XAndY[1] = -1;
}

void PrintOfWidth(int Width, const char *Data) {
	int Data1[2], Data2[2];
	GetCursorPosition(Data1);
	printf("%s", Data);
	GetCursorPosition(Data2);
	for (int i = 0; i < Width - (Data2[0] - Data1[0]); i++)
		printf(" ");
}

void PrintOfWidth_Right(int Width, const char *Data) {
	int Data1[2], Data2[2];
	GetCursorPosition(Data1);
	printf("%s", Data);
	GetCursorPosition(Data2);
	for (int i = 0; i < Data2[0] - Data1[0]; i++)
		printf("\b");
	for (int i = 0; i < Width - (Data2[0] - Data1[0]); i++)
		printf(" ");
	printf("%s", Data);
}