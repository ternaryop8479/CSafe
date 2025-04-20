/*
 * Log.h
 * ������־�����API��װ
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
std::mutex logMutex; // ���ڱ���Log�Ļ�����

bool LogInit(void) {
	const time_t StartLogTime = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡ��ǰʱ��

	ostringstream timeStr;//��ǰʱ��
	timeStr << put_time(localtime(&StartLogTime), "%Y.%m.%d-%H_%M_%S");//��ȡ��ǰʱ���sstream��ʽ

	LogFileName = "Logs\\" + timeStr.str() + (string)".log";//ת��Ϊ��־�ļ���

	FILE *CreateLogFile = fopen(LogFileName.c_str(), "w+");//������־�ļ�
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
void log_info(const T &value, const Args &... args) {//ʵ�ʵ��õ��ĺ���
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //����̨�������
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//�ļ����
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//����̨���

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//����̨���δ����
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][info] ";//�ļ����

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log_error(const T &value, const Args &... args) {//ʵ�ʵ��õ��ĺ���
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //����̨�������
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//�ļ����
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//����̨���

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//����̨���δ����
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][error] ";//�ļ����

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log_warn(const T &value, const Args &... args) {//ʵ�ʵ��õ��ĺ���
	std::lock_guard<std::mutex> lock(logMutex);
	if (IsConsoleOutOK) { //����̨�������
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//�ļ����
		cout << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//����̨���

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;
		cout << endl;

		mylog.close();
	} else {//����̨���δ����
		ofstream mylog(LogFileName, ios_base::app); // ��׷��ģʽ���ļ�

		time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());//��ȡʱ��

		mylog << "[" << put_time(localtime(&now), "%Y-%m-%d %H:%M:%S") << "][warn] ";//�ļ����

		__log(mylog, value, args...);//�ݹ��ȥ���ʣ�µ�����

		mylog << endl;

		mylog.close();
	}
}

template <typename T, typename... Args>
void log(const T &value, const Args &... args) {//ʵ�ʵ��õ��ĺ���
	log_info(value, args...);//��װһ��info
}