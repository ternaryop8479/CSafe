/*
 * Authority.h
 * ����ɱ�������Ȩ�õĺ���
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <Windows.h>

bool GetAdmin(int Showcmd) {//��ȡ����ԱȨ��
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;  //�ж��Ƿ��й���ԱȨ��
	PSID AdministratorsGroup;
	BOOL b = AllocateAndInitializeSid(
	             &NtAuthority,
	             2,
	             SECURITY_BUILTIN_DOMAIN_RID,
	             DOMAIN_ALIAS_RID_ADMINS,
	             0, 0, 0, 0, 0, 0,
	             &AdministratorsGroup);
	if (b) {
		CheckTokenMembership(NULL, AdministratorsGroup, &b);
		FreeSid(AdministratorsGroup);
	}

	if (b == TRUE)
		return 0;
	TCHAR Path[MAX_PATH];
	ZeroMemory(Path, MAX_PATH);
	::GetModuleFileName(NULL, Path, MAX_PATH);           //��ȡ����·��
	HINSTANCE res;
	res = ShellExecute(NULL, "runas", Path, NULL, NULL, Showcmd);
	exit(0);
	if ((int)res > 32)
		return 1;
	else
		return 0;
}

bool GetDebugPrivilege() {//��ȡDebugȨ��
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return   false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}
	return true;
}