/*
 * main.cpp
 * ���ļ�
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "HeadFile/Initalization.h"//���ͷ�ļ��Լ�����main����ִ��֮ǰ�ĳ�ʼ���������Ȩ������������Ȳ�������Ҫ����
#include "HeadFile/MainAntivirus.h"
#include "HeadFile/MainUI.h"

int main(int argc, char *argv[]) {
	if (argc > 1 && std::string(argv[1]) == "--quiet") {
		quietMode = true;
	}

	if (!quietMode) { // ��Ĭģʽ����ȡ����ԱȨ�ޣ�Ҫ��Ŀ����������ý���ʱ�������ԱȨ��
		GetAdmin(SW_SHOW);
	}

	LogInit();
	log("Initialization: Start init.");

	log("Initialization: Set window protect...");
//	DisableCloseButton();//���ùرհ�ť(���û����ֹ���ھ�������������̣�ֻ���������ֲе�)
	SetConsoleCtrlHandler(shieldHandler, TRUE);//���ý���Ctrl+C/Ctrl+Z��ݼ��������̣�ע�������������MainUI.h��

	log("Initialization: Set current directory...");
	char Name[MAX_PATH] = { 0 };
	DWORD resultGetModuleFileNameA = GetModuleFileNameA(NULL, Name, MAX_PATH);
	if (resultGetModuleFileNameA == 0) {
		log_error("Initialization: Failed to get the current path: ", GetLastError());
	}
	(_tcsrchr(Name, _T('\\')))[0] = 0;//ɾ���ļ�����ֻ���·�� �ִ�
	log("Initialization: Current directory: ", Name);
	_chdir(Name);
	_chdrive(Name[0]);
	char Pathcmd[MAX_PATH];
	sprintf(Pathcmd, "cd /d %s", Name);
	system(Pathcmd);
	DWORD resultSetModuleFileNameA = SetCurrentDirectoryA(Name);
	if (resultSetModuleFileNameA == 0) {
		log_error("Initialization: Failed to set the current path: ", GetLastError());
	}

	log("Initialization: Get the priviledges...");
	if (!GetDebugPrivilege()) {
		log_error("Initialization: Failed to get the privilege!");
	}

	if (!quietMode) {
		// ����������
		log("Set startup items...");
		if (!SetStart(true)) {
			log_error("Initialization: Failed to set the startup item!");
		}

		//���ô��ڱ���
		log("Initialization: Set window title...");
		SetConsoleTitle(TEXT("CSafe"));

		//�Ƴ����ٱ༭
		log("Initialization: Disable FastMake...");
		DisableFastMake();

		// ��������ͼ��
		log("Starting notify icon...");
		std::thread NotifyIconThread(keepNotifyIcon);
		NotifyIconThread.detach();
	} else {
		// ��Ĭģʽ������������
		log("Delete startup items...");
		if (!SetStart(false)) {
			log_error("Initialization: Failed to delete the startup item!");
		}
	}

	//���س�������
	log("Initialization: Loading settings...");
	if (fopen("CSafeData\\CSafeSetting.csdata", "r") == NULL) {
		log_warn("Initialization: No setting file! Create it.");
		CSafeAntivirusEngine::WhiteProtectSensitiveValue = 0.7081;
		CSafeAntivirusEngine::BITProtectBlackWeight = 0.512;
		CSafeAntivirusEngine::LSProtectEnableSensitiveMode = false;
		saveSetting();
	} else {
		loadSetting();
	}

	//ԭ������һ��������������Ӱ������Ĺ��ܣ�������Ϊ�о�̬�����ӳֲ��Ҵ����������˹���Ա���̣������󱨣����û�мӰ�����

	log("Initialization: Detection MBR backup...");
	if (!fopen("CSafeData\\MBRData.data", "rb")) {
		log_warn("Initialization: MBR is not backed up! Backuping...");
		CopyMBR();
	} else {
		log("MBR has been backuped.");
	}

	log("Detecting CSafe whether it's been on running...");
	HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//���������ڴ�
	char buffer[MAX_MAPSIZE];
	ReadMap(Map, buffer, MAX_MAPSIZE);
	if (buffer[0] == 1) {
		log_error("CSafe is already running!");
		return 1;
	}
	buffer[0] = 1;
	WriteMap(Map, buffer, MAX_MAPSIZE);

	// ��̬����
	log("Starting Dynamic Engine...");
	std::thread DynamicDetectThread(DynamicAntivirusThread);
	DynamicDetectThread.detach();

	// ��̬����
	log("Starting Static Engine...");
	std::thread StaticDetectThread(FileAntivirusThread);
	StaticDetectThread.detach();

	// ����������
	log("Entering main UI...");
	MainUI(); // ����������

	log("Main UI exit!");
	log("Exiting...");
	return 0;
}