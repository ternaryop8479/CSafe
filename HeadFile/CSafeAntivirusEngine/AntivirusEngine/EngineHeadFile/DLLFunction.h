/*
 * DLLFunction.h
 * 用来加载DLL中的函数
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <Windows.h>
#include <string>
#include <stdexcept>

class toDLLFunction {
	private:
		FARPROC Function = nullptr;
		HMODULE hmModule;
//		_OVERLAPPED Oapped;
//		HANDLE hDir;

		void Error(std::string ei) {
			MessageBeep(MB_ICONERROR);
			MessageBox(NULL, ei.data(), NULL, MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
			for (int i = 0; i < ei.size(); (ei[i] == '\n') ? ei.erase(i, 1) : "", ++i);
			throw std::runtime_error(ei.data());
			exit(1);
		}

	public:
		toDLLFunction(std::string DLLPath, std::string FunctionName) {
			this->hmModule = LoadLibraryA(DLLPath.data());
			if (this->hmModule == NULL) {
				this->Error("Error to load DLL \"" + DLLPath + "\", \nPlease reinstall the program or try to fix it.");
			}
			this->Function = GetProcAddress(hmModule, FunctionName.data());
			if (this->Function == NULL) {
				this->Error("Error to load function \"" + FunctionName + "\", the DLL file maybe broken. \nPlease reinstall the program or try to fix it.");
			}

//			this->hDir = CreateFile(DLLPath.data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
//			bool result = LockFileEx(this->hDir, LOCKFILE_EXCLUSIVE_LOCK, (DWORD)0, (DWORD)0, (DWORD)1024, &this->Oapped);
//			if(!result) {
//				this->Error("Error to lock the DLL \"" + DLLPath + "\", \nPlease reboot OS or reinstall the program to fix it.");
//			}
		}
		~toDLLFunction() {
//			UnlockFileEx(this->hDir, (DWORD)0, (DWORD)0, (DWORD)1024, &this->Oapped);
//			CloseHandle(hDir);
			FreeLibrary(hmModule);
		}

		FARPROC getFuntion(void) {
			return this->Function;
		}
};