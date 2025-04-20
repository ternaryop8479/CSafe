/*
 * Log.h
 * 包含日志输出的API封装
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#pragma once

#include <ctime>
#include <string>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ostream>
#include <mutex>

using namespace std;

string LogFileName;
volatile bool IsConsoleOutOK = true;
std::mutex logMutex; // 用于保护Log的互斥锁

bool LogInit(void) {
	const time_t StartLogTime = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取当前时间

	ostringstream timeStr;//当前时间
	timeStr << put_time(localtime(&StartLogTime), "%Y.%m.%d-%H_%M_%S");//获取当前时间的sstream形式

	LogFileName = "Logs\\" + timeStr.str() + (string)".log";//转换为日志文件名

	FILE *CreateLogFile = fopen(LogFileName.c_str(), "w+");//创建日志文件
	if (CreateLogFile == NULL) {
		fclose(CreateLogFile);
		return false;
	}
	fclose(CreateLogFile);
	return true;
}

template <typename T>
void __log(ofstream &file, const T &value) {
	file << value;
	if (IsConsoleOutOK)
		cout << value;
}

template <typename T, typename... Args>
void __log(ofstream &file, const T &value, const Args &... args) {
	file << value;
	if (IsConsoleOutOK)
		cout << value;
	__log(file, args...);
}

template <typename T, typename... Args>
void log_info(const T &value, const Args &... args) {//实际调用到的函数
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //控制台输出启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//文件输出
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//控制台输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//控制台输出未启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//文件输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log_error(const T &value, const Args &... args) {//实际调用到的函数
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //控制台输出启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//文件输出
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//控制台输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//控制台输出未启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//文件输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log_warn(const T &value, const Args &... args) {//实际调用到的函数
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //控制台输出启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//文件输出
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//控制台输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//控制台输出未启用
		ofstream mylog(LogFileName, ios_base::app); // 以追加模式打开文件

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//获取时间

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//文件输出

		__log(mylog, value, args...);//递归出去输出剩下的数据

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log(const T &value, const Args &... args) {//实际调用到的函数
	log_info(value, args...);//封装一下info
}