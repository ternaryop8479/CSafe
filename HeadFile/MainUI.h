/*
 * MainUI.h
 * 包含主要UI界面的定义
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <conio.h>
#include <iostream>
#include <utility>
#include <tuple>
#include "MainAntivirus.h"
#include "AntivirusSoftHeadFile/Log.h"
#include "VirusHandle.h"
#include "AntivirusSoftHeadFile/MBR.h"
#include "AntivirusSoftHeadFile/Console.h"
#include <Windows.h>
#include <tlhelp32.h>
#include "AntivirusSoftHeadFile/Terminal.h"
#include "AntivirusSoftHeadFile/ProcessHandle.h"
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)//检测按键

//获取进程内存占用
size_t GetProcessMemorySize(DWORD processID) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (hProcess == NULL) {
		return 0;
	}

	PROCESS_MEMORY_COUNTERS pmc;
	if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
		size_t size = pmc.WorkingSetSize;
		CloseHandle(hProcess);
		return size;
	}

	CloseHandle(hProcess);
	return 0;
}

static volatile bool leftButton = false, rightButton = false;

void HideUI(void) {
	log("Hiding main window...");
	Sleep(256);//让用户注意到输出
	HWND MainHwnd = GetConsoleWindow();
	ShowWindow(MainHwnd, SW_HIDE);
	log("Main window is hidden!"/*, " You can use \"Ctrl + Alt + C\" to wake up the window!"*/);
//	MessageBox(NULL, "窗体已隐藏！您可以使用Ctrl + Alt + C键召出窗体！", "CSafe安全", MB_OK);

	while (true) {
		if (KEY_DOWN(VK_CONTROL)) {//检测显示窗体快捷键
			if (KEY_DOWN(VK_MENU)) {
				if (KEY_DOWN(VK_C)) {
					log("Wake up main window...");
					ShowWindow(MainHwnd, SW_SHOW);
					return;
				}
			}
		}
		if (rightButton) {
			rightButton = false;
		}
		if (leftButton) {
			leftButton = false;
			log("Wake up main window...");
			ShowWindow(MainHwnd, SW_SHOW);
			return;
		}
		Sleep(100);//这里Sleep不影响正常查杀，因为是分线程的
	}
}

//托盘图标的消息处理
void HandleTrayMessage(HWND hWnd, UINT message) {
	switch (message) {
		case WM_LBUTTONUP://鼠标左键点击托盘图标
			leftButton = true;
			break;

		case WM_RBUTTONUP:
			rightButton = true;
			break;

		default:
			break;
	}
}

//托盘图标
LRESULT CALLBACK WindowProcedure(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	switch (message) {
		case WM_USER + 1: // 托盘图标消息
			HandleTrayMessage(hWnd, lParam);
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}
//设置托盘图标(注：闭锁函数，需要单开线程维护)
char *CLASS_NAME;
HINSTANCE hInstance;
NOTIFYICONDATA nid;
MSG msg;
void keepNotifyIcon() {
	CLASS_NAME = new char[6];
	strcpy(CLASS_NAME, "CSafe");
	hInstance     = GetModuleHandle(NULL);

	WNDCLASSEX wc = {};

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WindowProcedure;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszClassName = CLASS_NAME;

	if (!RegisterClassEx(&wc)) {
		return;
	}

	// 创建隐藏窗口
	HWND hWnd = CreateWindowExA(
	                WS_EX_TOOLWINDOW,
	                CLASS_NAME,
	                "CSafe Hidden Window",
	                WS_POPUP,
	                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
	                NULL, NULL, hInstance, NULL
	            );

	if (hWnd == NULL) {
		return;
	}

	ShowWindow(hWnd, SW_HIDE); // 隐藏窗口

	// 创建系统托盘图标
	nid = {};
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = hWnd;
	nid.uID = 1;
	nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	nid.uCallbackMessage = WM_USER + 1;
	nid.hIcon = (HICON)LoadImageA(NULL, "CSafeData\\CSafe_Small.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
	strcpy(nid.szTip, "CSafe");

	Shell_NotifyIcon(NIM_ADD, &nid); // 创建托盘图标

	msg = {};
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

void destoryNotifyIcon() {
	Shell_NotifyIcon(NIM_DELETE, &nid); // 删除托盘图标
	UnregisterClass(CLASS_NAME, hInstance);
	delete[] CLASS_NAME;
}

//处理扫描到的病毒
void Handler(std::string path, std::string riskLevel) {
	log("Scanning file: ", path);
	if (riskLevel.find("Error") == std::string::npos && riskLevel.find("disVirus") == std::string::npos && !WhiteList(path)) {
		log("\n================================\n",
		    "Scanned a virus file! \nFile path: ", path, "\n",
		    "Virus type: ", riskLevel, "\n",
		    "================================\n");
		IsolateFile(path);
	}
}

BOOL WINAPI shieldHandler(DWORD signal) { // 最终的析构函数
	switch (signal) {
		default: {
			saveSetting();
			destoryNotifyIcon();

			HANDLE Map = CreateMap_NoProcess("CSafeRunned", MAX_MAPSIZE);//创建共享内存
			char buffer[MAX_MAPSIZE];
			buffer[0] = 0;
			WriteMap(Map, buffer, MAX_MAPSIZE);
			DeleteMap(Map);

			return TRUE;
		}
	}
	return FALSE;
}

std::pair<std::string, std::vector<std::string>> resolveCommand(const std::string &commandLine) {
	std::pair<std::string, std::vector<std::string>> result;
	bool paramCounter = false, isFirstArg = true;
	size_t paramIndex = 0;
	for (int i = 0; i < commandLine.size(); ++i) {
		if (isFirstArg) {
			if (commandLine[i] == ' ') {
				if (i != commandLine.size() - 1 && commandLine[i + 1] != '[') {
					return std::make_pair("ERROR", std::vector<std::string>(1, "ILLEGAL_ARGUMENT_FORMAT"));
				}
				isFirstArg = false;
				result.second.resize(paramIndex + 1);
			} else {
				result.first += commandLine[i];
			}
		} else if (commandLine[i] == '[') {
			if (paramCounter) {
				return std::make_pair("ERROR", std::vector<std::string>(1, "ILLEGAL_ARGUMENT_FORMAT"));
			}
			paramCounter = true;
		} else if (commandLine[i] == ']') {
			if ((i != commandLine.size() - 1 && commandLine[i + 1] != ' ') || (i != commandLine.size() - 1 && i != commandLine.size() - 2 && commandLine[i + 2] != '[')) {
				return std::make_pair("ERROR", std::vector<std::string>(1, "ILLEGAL_ARGUMENT_FORMAT"));
			}
			paramCounter = false;
			++paramIndex;
			result.second.resize(paramIndex + 1);
		} else {
			if (paramCounter) {
				if (commandLine[i - 1] == '[' && (commandLine[i] == '\"' || commandLine[i] == '\'')) {
					continue;
				} else if (i != commandLine.size() - 1 && commandLine[i + 1] == ']' && (commandLine[i] == '\"' || commandLine[i] == '\'')) {
					continue;
				}
				result.second[paramIndex] += commandLine[i];
			}
		}
	}
	if (!result.second.empty()) {
		result.second.resize(result.second.size() - 1);
	}

	return result;
}

const size_t MAX_COMMAND_SIZE = 8192;

void MainUI(bool enableNoUI = false) {
	log("================================================");
	log("Welcome to the CSafe security software!");
	log("Copyright (C) 2022 Ternary_Operator");
	log("CSafe website address: https://csafe.pages.dev/");
	log("================================================");
commandline:
	IsConsoleOutOK = true;
	log("Press \"c\" to enter the console, type \"help\" in the console to get help.");
	if (fopen("CSafeData\\isFirstRunned", "r") != NULL && !quietMode) {
		HideUI();
	} else {
		FILE *fp = fopen("CSafeData\\isFirstRunned", "w+");
		fclose(fp);
	}
	while (true) {
		if (!_kbhit()) {
			if (leftButton) { //左键单击托盘显示UI
				leftButton = false;
			}
			if (rightButton) { //右键单击托盘隐藏UI
				leftButton = false;
				HideUI();
			}
			continue;
		}
		char CtrlChar = getch();
		if (CtrlChar != 'c' && CtrlChar != 'C')
			continue;
		log("Enter the console...");
		while (true) {
			IsConsoleOutOK = false;//关闭日志输出
			std::string commandline;
			char params_str[MAX_COMMAND_SIZE] = {0}; // 命令行和解析之后的参数字符串
			char ccommand[MAX_COMMAND_SIZE] = {0}; // 命令
			std::vector<std::string> params; // 参数数组
			std::cout << "[CSafe Console]$ >.";
			std::getline(std::cin, commandline);
			parse_commandline(commandline.data(), params_str, MAX_COMMAND_SIZE); // 解析命令行至参数字符串
			parse_param(ccommand, params_str, 0); // 解析出命令
			char paramTemp[MAX_COMMAND_SIZE] = {0};
			for (size_t i = 1; parse_param(paramTemp, params_str, i); ++i) { // 解析参数
				params.push_back(paramTemp);
			}
			std::string command = ccommand; // 命令(std::string)
			log("Run command:", "\"", command, "\"");
			IsConsoleOutOK = true;//启用日志输出

			if (command == "help" || command == "HELP") {
				std::cout << "help---------------------Get help." << std::endl;
				std::cout << "exitcm-------------------Exit the CSafe console." << std::endl;
				std::cout << "exit---------------------Exit the CSafe Antivirus Software." << std::endl;
				std::cout << "=======================AntivirusEngine commands=======================" << std::endl;
				std::cout << "start--------------------Start antivirus engine." << std::endl;
				std::cout << "stop---------------------Stop antivirus engine." << std::endl;
				std::cout << "setting------------------Set the antivirus engine settings." << std::endl;
				std::cout << "save---------------------Save the settings that you set." << std::endl;
				std::cout << "scan---------------------Scan a folder" << std::endl;
				std::cout << "fscan--------------------Do a quick scan for a folder" << std::endl;
				std::cout << "rembr--------------------Restore MBR startup information." << std::endl;
				std::cout << "addlist------------------Add a new whitelist exception." << std::endl;
				std::cout << "whitelist----------------View whitelist exceptions." << std::endl;
				std::cout << "isozone------------------View all files in the isolated zone." << std::endl;
				std::cout << "release------------------Release the file from the isolated zone." << std::endl;
				std::cout << "hide---------------------Hide Main Window." << std::endl;
				std::cout << "detectproc---------------Get the risk type of a process." << std::endl;
				std::cout << "detectfile---------------Detect a target file." << std::endl;
				std::cout << "========================System Control commands=======================" << std::endl;
				std::cout << "list---------------------List all processes." << std::endl;
				std::cout << "getpath------------------Get the path of a process." << std::endl;
				std::cout << "topid--------------------Get the process id of a process with its' name" << std::endl;
				std::cout << "kill---------------------Kill a process even if it's not a virus." << std::endl;
				std::cout << "remove-------------------Delete a file(May need reboot or not)." << std::endl;
				std::cout << "lock---------------------Lock a process even if it's not a virus." << std::endl;
				std::cout << "unlock-------------------Unlock a process." << std::endl;
				std::cout << "hash---------------------Get SHA-256 hash code from a file." << std::endl;
			} else if (command == "exitcm" || command == "EXITCM") {
				goto commandline;
			} else if (command == "exit" || command == "EXIT") {
				shieldHandler(0);
				return;
			} else if (command == "start" || command == "START") {
				if (params.empty()) {
					log_error("Usage: start [--all/--dynamic/--static]");
					continue;
				}
				if (params[0] == "--all") {
					log("Start all of the antivirus engine.");
					EnableDynamicEngine = true, EnableStaticEngine = true;
				} else if (params[0] == "--dynamic") {
					log("Start dynamic antivirus engine.");
					EnableDynamicEngine = true;
				} else if (params[0] == "--static") {
					log("Start static antivirus engine.");
					EnableStaticEngine = true;
				} else {
					log_error("Illegal param format.");
				}
			} else if (command == "stop" || command == "STOP") {
				if (params.empty()) {
					log_error("Usage: stop [--all/--dynamic/--static]");
					continue;
				}
				if (params[0] == "--all") {
					log("Stop all of the antivirus engine.");
					EnableDynamicEngine = false, EnableStaticEngine = false;
				} else if (params[0] == "--dynamic") {
					log("Stop dynamic antivirus engine.");
					EnableDynamicEngine = false;
				} else if (params[0] == "--static") {
					log("Stop static antivirus engine.");
					EnableStaticEngine = false;
				} else {
					log_error("Illegal param format.");
				}
			} else if (command == "setting" || command == "SETTING") {
				if (params.empty()) {
					log_error("\nUsage: \n",
					          "setting [--lsprotect/--bitprotect/--whiteprotect] ...\n",
					          "setting [--lsprotect]: \n",
					          "    setting [--lsprotect] [enable/disable] [engine/highmode]\n",
					          "setting [--bitprotect]: \n",
					          "    setting [--bitprotect] setvalue (Sensitive Value)\n",
					          "setting [--whiteprotect]: \n",
					          "    setting [--whiteprotect] setvalue (Sensitive Value)\n",
					          "P.S. With BITProtect, more sensitive value, more killed, with WhiteProtect, more sensitive value, less killed. Enable LSProtect HighMode will improve killed number.");
					continue;
				}
				if (params.size() != 3) {
					log_error("Illegal param format.");
				}
				if (params[0] == "--lsprotect") {
					if (params[1] == "enable") {
						if (params[2] == "engine") {
							log("Enable the LSProtect.");
							CSafeAntivirusEngine::EnableLSProtect = true;
						} else if (params[2] == "highmode") {
							log("Enable the LSProtect high sensitive mode.");
							CSafeAntivirusEngine::enableLSProtectSensitiveMode();
						} else {
							log_error("Illegal param format.");
						}
					} else if (params[1] == "disable") {
						if (params[2] == "engine") {
							log("Disable the LSProtect.");
							CSafeAntivirusEngine::EnableLSProtect = false;
						} else if (params[2] == "highmode") {
							log("Disable the LSProtect high sensitive mode.");
							CSafeAntivirusEngine::disableLSProtectSensitiveMode();
						} else {
							log_error("Illegal param format.");
						}
					} else {
						log_error("Illegal param format.");
					}
				} else if (params[0] == "--bitprotect") {
					if (params[1] == "setvalue") {
						log("Set the BITProtect sensitive value with ", std::stod(params[2]));
						CSafeAntivirusEngine::setBITProtectWeight(std::stod(params[2]));
					} else {
						log_error("Illegal param format.");
					}
				} else if (params[0] == "--whiteprotect") {
					if (params[1] == "setvalue") {
						log("Set the WhiteProtect sensitive value with ", std::stod(params[2]));
						CSafeAntivirusEngine::WhiteProtectSensitiveValue = std::stod(params[2]);
					} else {
						log_error("Illegal param format.");
					}
				} else {
					log_error("Illegal param format.");
				}
			} else if (command == "save" || command == "save") {
				saveSetting();
			} else if (command == "scan" || command == "SCAN") {
				if (params.empty()) {
					log_error("Usage: scan (Target Folder Path)");
					continue;
				}
				try {
					std::cout << "Scanning " << params[0] << std::endl;
					CSafeAntivirusEngine::scanFolder(params[0], Handler);
				} catch (const std::runtime_error &e) {
					log_error("Something went wrong in scanning! e.what(): ", e.what());
				}
			} else if (command == "fscan" || command == "FSCAN") {
				if (params.empty()) {
					log_error("Usage: fscan (Target Folder Path)");
					continue;
				}
				try {
					std::cout << "Scanning " << params[0] << std::endl;
					CSafeAntivirusEngine::scanFolder(params[0], Handler, true);
				} catch (const std::runtime_error &e) {
					log_error("Something went wrong in scanning! e.what(): ", e.what());
				}
			} else if (command == "rembr" || command == "REMBR") {
				IsConsoleOutOK = false;
				std::cout << "Sure to restore MBR? (Y/n)";
				char ch;
				if (!params.empty() && params[0] == "--yes") {
					ch = 'Y';
				} else {
					std::cin >> ch;
					std::cin.ignore();
				}
				IsConsoleOutOK = true;
				if (ch == 'Y') {
					bool doOK = ReMBR();
					log("Restore the MBR! ", doOK);
				}
			} else if (command == "addlist" || command == "ADDLIST") {
				if (params.empty()) {
					log_error("Usage: addlist (Target File/Folder Name)");
					continue;
				}
				try {
					if (WriteList(params[0])) {
						log("Add successfully!");
					} else {
						log("Add failed!");
					}
				} catch (const std::runtime_error &e) {
					log_error("Something went wrong in scanning! e.what(): ", e.what());
				}
			} else if (command == "whitelist") {
				std::ifstream WhiteList("CSafeData\\WhiteList.csdata");
				std::string LineData;
				while (std::getline(WhiteList, LineData)) {
					std::cout << LineData << std::endl;
				}
			} else if (command == "isozone") {
				std::cout << "There is the hash code and origin path of the isolated files: " << std::endl;
				std::vector<std::pair<std::string, std::string>> FileList;
				try {
					FileList = ExportIsolatedFileList();
					for (int i = 0; i < FileList.size(); ++i) {
						std::cout << i << "     " << FileList[i].first << "     " << FileList[i].second << std::endl;
					}
				} catch (const std::runtime_error &e) {
					log_error("Catch a error during ergodicing isolated zone data!");
				}
			} else if (command == "release") {
				if (params.empty()) {
					log_error("Usage: release [--num=(The File Number in \"isozone\" command) / --hash=(The Hash Code of Target File)] [--to=(where the file will released to, not add this parameter to release to the original location)]");
					continue;
				}
				if (params.size() > 2) {
					log_error("Illegal param format.");
					continue;
				}
				std::string hash;
				std::string targetLocation;
				if (params[0].find("--num=") != std::string::npos) {
					try {
						size_t num = std::stoi(params[0].substr(params[0].find("--num=") + 6));
						hash = ExportIsolatedFileList()[num].first;
					} catch (const std::runtime_error &e) {
						log_error("Something went wrong during ergodicing isolated zone! Error details: ", e.what());
					}
				} else if (params[0].find("--hash=") != std::string::npos) {
					hash = params[0].substr(params[0].find("--hash=") + 7);
				} else if (params[0].find("--to=") != std::string::npos) {
					targetLocation = params[0].substr(params[0].find("--to=") + 5);
				} else {
					log_error("Illegal param format.");
					continue;
				}
				if (params.size() == 2) {
					if (params[1].find("--num=") != std::string::npos) {
						try {
							size_t num = std::stoi(params[1].substr(params[1].find("--num=") + 6));
							hash = ExportIsolatedFileList()[num].first;
						} catch (const std::runtime_error &e) {
							log_error("Something went wrong during ergodicing isolated zone! Error details: ", e.what());
						}
					} else if (params[1].find("--hash=") != std::string::npos) {
						hash = params[1].substr(params[1].find("--hash=") + 7);
					} else if (params[1].find("--to=") != std::string::npos) {
						targetLocation = params[1].substr(params[1].find("--to=") + 5);
					} else {
						log_error("Illegal param format.");
						continue;
					}
				}
				log("Releasing file with hash code ", hash);
				try {
					if (targetLocation.empty()) {
						ReleaseFile(hash);
					} else {
						ReleaseFile(hash, false, targetLocation);
					}
				} catch (const std::runtime_error &e) {
					log_error("Release failed! Error details: ", e.what());
				}
				log("Relese done.");
			} else if (command == "hide" && !quietMode) {
				HideUI();
				goto commandline;//默认为显示窗口之后退出命令行界面
			} else if (command == "detectproc") {
				if (params.empty()) {
					log_error("Usage: detectproc (Target ProcessID)");
					continue;
				}
				PROCESSENTRY32 pe32 = PIDtoEntry32(std::stoi(params[0]));
				if (pe32.dwSize == 0) {
					log("Failed to get process handle! Please check your process id for input!");
					continue;
				}
				IsConsoleOutOK = false;//关闭日志输出
				std::cout << "Monitoring target process..." << std::endl;
				TOProtectInfo processInfo = CSafeAntivirusEngine::detectProcess(pe32);
				std::cout << "Process risk type: " << processInfo.expectedType << std::endl;
				std::cout << "Process risk level: " << processInfo.riskLevel << std::endl;
				IsConsoleOutOK = true;//启用日志输出
			} else if (command == "detectfile") {
				if (params.empty()) {
					log_error("Usage: detectfile (Target File Path)");
					continue;
				}
				std::string riskLevel = CSafeAntivirusEngine::detectFile(params[0]);
				std::cout << "Risk type: " << riskLevel << std::endl;
			} else if (command == "list") {
				PrintOfWidth(32, "Name");
				PrintOfWidth_Right(8, "   PID");
				PrintOfWidth_Right(8, "   Thread Count");
				PrintOfWidth_Right(8, "   Priority");
				PrintOfWidth_Right(12, "    Mem");
				printf("\n");

				for (int i = 0; i < 68; i++) //30+10+8+8+10=66
					printf("=");

				printf("\n");
				HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};

				while (Process32Next(hProcessSnap, &process)) {
					PrintOfWidth(32, process.szExeFile);
					PrintOfWidth_Right(8, to_string(process.th32ProcessID).c_str());
					PrintOfWidth_Right(8, to_string(process.cntThreads).c_str());
					PrintOfWidth_Right(8, to_string(process.pcPriClassBase).c_str());
					string Temp = to_string(int(double((double)GetProcessMemorySize(process.th32ProcessID) / 1024.0))) + " KB";
					PrintOfWidth_Right(12, Temp.c_str());
					printf("\n");
				}

				printf("P.S. Data from some system processes may experience exceptions.\n");
			} else if (command == "getpath") {
				if (params.empty()) {
					log_error("Usage: getpath (Target Process ID)");
					continue;
				}
				try {
					std::cout << "Process path: " << GetProcessFullPath(std::stoi(params[0])) << std::endl;
				} catch (const std::runtime_error &e) {
					log_error("Something went wrong in calculation! e.what(): ", e.what());
				}
			} else if (command == "topid") {
				if (params.empty()) {
					log_error("Usage: topid (Target Process FileName)");
					continue;
				}
				std::cout << "Process id: " << NameToPID(params[0].c_str()) << std::endl;
			} else if (command == "kill") {
				if (params.empty()) {
					log_error("Usage: kill (Target Process ID)");
					continue;
				}
				log("Kill: ", ForceTerminateProcess(std::stoi(params[0])) ? "success" : "failed");
			} else if (command == "remove") {
				if (params.empty()) {
					log_error("Usage: remove (Target File Full Path)");
					continue;
				}
				log("Remove: ", (remove(params[0].c_str()) == 0 ? 1 : forceRemove(params[0])) ? "success" : "failed");
				std::cout << "Please reboot if target file is not deleted now." << std::endl;
			} else if (command == "lock") {
				if (params.empty()) {
					log_error("Usage: lock (Target Process ID)");
					continue;
				}
				log("Lock: ", PauseProcess(std::stoi(params[0]), true) ? "success" : "failed");
			} else if (command == "unlock") {
				if (params.empty()) {
					log_error("Usage: unlock (Target Process ID)");
					continue;
				}
				log("Unlock: ", PauseProcess(std::stoi(params[0]), false) ? "success" : "failed");
			} else if (command == "hash") {
				if (params.empty()) {
					log_error("Usage: hash (Target File Full Path)");
					continue;
				}
				std::cout << "SHA-256 Hash code: " << calculate_file_sha256(params[0]) << std::endl;
			} else {
				log_error("Unknown command.");
			}
		}
		Sleep(100);//这里Sleep不影响正常查杀，因为是分线程的
	}
}