/*
 * main.cpp
 * 主文件
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#include "HeadFile/Initalization.h"//这个头文件自己会有main函数执行之前的初始化，因此提权、设置启动项等操作不需要处理
#include "HeadFile/MainAntivirus.h"
#include "HeadFile/MainUI.h"

int main(int argc, char *argv[]) {
	if (argc > 1 && std::string(argv[1]) == "--quiet") {
		quietMode = true;
	}

	if (!quietMode) { // 静默模式不获取管理员权限，要求目标进程启动该进程时给予管理员权限
		GetAdmin(SW_SHOW);
	}

	LogInit();
	log("Initialization: Start init.");

	log("Initialization: Set window protect...");
//	DisableCloseButton();//禁用关闭按钮(这个没法防止窗口句柄攻击结束进程，只是用来防手残的)
	SetConsoleCtrlHandler(shieldHandler, TRUE);//设置禁用Ctrl+C/Ctrl+Z快捷键结束进程，注意这个处理函数在MainUI.h里

	log("Initialization: Set current directory...");
	char Name[MAX_PATH] = { 0 };
	DWORD resultGetModuleFileNameA = GetModuleFileNameA(NULL, Name, MAX_PATH);
	if (resultGetModuleFileNameA == 0) {
		log_error("Initialization: Failed to get the current path: ", GetLastError());
	}
	(_tcsrchr(Name, _T('\\')))[0] = 0;//删除文件名，只获得路径 字串
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
		// 设置启动项
		log("Set startup items...");
		if (!SetStart(true)) {
			log_error("Initialization: Failed to set the startup item!");
		}

		//设置窗口标题
		log("Initialization: Set window title...");
		SetConsoleTitle(TEXT("CSafe"));

		//移除快速编辑
		log("Initialization: Disable FastMake...");
		DisableFastMake();

		// 加载托盘图标
		log("Starting notify icon...");
		std::thread NotifyIconThread(keepNotifyIcon);
		NotifyIconThread.detach();
	} else {
		// 静默模式不设置启动项
		log("Delete startup items...");
		if (!SetStart(false)) {
			log_error("Initialization: Failed to delete the startup item!");
		}
	}

	//加载程序设置
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

	//原本会有一个检测白名单并添加白名单的功能，但是因为有静态启发加持并且处理函数过滤了管理员进程，不易误报，因此没有加白名单

	log("Initialization: Detection MBR backup...");
	if (!fopen("CSafeData\\MBRData.data", "rb")) {
		log_warn("Initialization: MBR is not backed up! Backuping...");
		CopyMBR();
	} else {
		log("MBR has been backuped.");
	}

	log("Detecting CSafe whether it's been on running...");
	HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//创建共享内存
	char buffer[MAX_MAPSIZE];
	ReadMap(Map, buffer, MAX_MAPSIZE);
	if (buffer[0] == 1) {
		log_error("CSafe is already running!");
		return 1;
	}
	buffer[0] = 1;
	WriteMap(Map, buffer, MAX_MAPSIZE);

	// 动态引擎
	log("Starting Dynamic Engine...");
	std::thread DynamicDetectThread(DynamicAntivirusThread);
	DynamicDetectThread.detach();

	// 静态引擎
	log("Starting Static Engine...");
	std::thread StaticDetectThread(FileAntivirusThread);
	StaticDetectThread.detach();

	// 加载主界面
	log("Entering main UI...");
	MainUI(); // 进入主界面

	log("Main UI exit!");
	log("Exiting...");
	return 0;
}