// Loadpe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

// LoadPe.cpp
#include <windows.h>
#include "LoadPe.h"

extern unsigned char pRawPeBlock[];
char *pzUnLoad = "UnLoad"; // the export function UnLoad name string;

						   // if function succed return the new thread handle, lphInstance point to the memPe instance, pfUnload point to the address to unload the instance
						   // otherwise return NULL;
HANDLE __stdcall LoadPeA(LPVOID lpRawRelocPe, LPCSTR lpCommandLine, HINSTANCE *phInst, BOOL fSuicid, PROCUNLOAD *pfUnload)
{
	HANDLE hRet = NULL;
	int nCmdLineLen = lstrlenA(lpCommandLine) + 1;
	PWCHAR pwCmdLine = (PWCHAR)_malloc(nCmdLineLen * sizeof(WCHAR));
	if (MultiByteToWideChar(CP_THREAD_ACP, MB_COMPOSITE, lpCommandLine, -1, pwCmdLine, nCmdLineLen))
		hRet = LoadPeW(lpRawRelocPe, pwCmdLine, phInst, fSuicid, pfUnload);
	_free(pwCmdLine);
	return hRet;
}

HANDLE __stdcall LoadPeW(LPVOID lpRawRelocPe, LPCWSTR lpwCommandLine, HINSTANCE *phInst, BOOL fSuicid, PROCUNLOAD *pfUnload)
{
	int nRet = ERROR_UNKNOWN;
	int nPeBlockImageSize = 0;
	int nRawRelocPeImageSize = 0;
	int nCmdLineLenA = 0; // the string length for commandlinea include the end flag.
	int nCmdLineLenW = 0;
	int nMemNead = 0;
	HANDLE hRet = 0;
	LPVOID lpPeBlock = NULL;
	LPVOID lpRelocPe = NULL;
	LPWSTR lpwCmdLine = NULL; // point to the WideByte commandline in lpPeblock
	LPSTR lpCommandLine = NULL; // multibyte commandline;
	LPSTR lpCmdLine = NULL; // point to the multibyte commandline in lpPeblock
	LPPEPARAM pPeParam = NULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	__try
	{
		if (lpwCommandLine == NULL)
			__leave;
		nCmdLineLenA = lstrlenW(lpwCommandLine);
		nCmdLineLenA += sizeof(CHAR);
		nCmdLineLenW = lstrlenW(lpwCommandLine) * sizeof(WCHAR);
		nCmdLineLenW += sizeof(WCHAR);
		lpCommandLine = (LPSTR)_malloc(nCmdLineLenA);
		if (0 == WideCharToMultiByte(CP_THREAD_ACP, 0, lpwCommandLine, -1, lpCommandLine, nCmdLineLenA, NULL, NULL))
			__leave;
		nRet = VerifyPE(pRawPeBlock);
		if (nRet)
			__leave;
		nRet = VerifyPE(lpRawRelocPe);
		if (nRet)
			__leave;

		pDosHeader = (PIMAGE_DOS_HEADER)pRawPeBlock;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		nPeBlockImageSize = pNTHeader->OptionalHeader.SizeOfImage;
		if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) // the pRawPeBlock should not be a Dll
		{
			nRet = ERROR_INVALID_MEMPEBLOCK;
			__leave;
		}
		pDosHeader = (PIMAGE_DOS_HEADER)lpRawRelocPe;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		LPVOID pImageBase = (LPVOID)(ULONG_PTR)pNTHeader->OptionalHeader.ImageBase;
		nRawRelocPeImageSize = pNTHeader->OptionalHeader.SizeOfImage;

		nMemNead = nRawRelocPeImageSize + nPeBlockImageSize + nCmdLineLenA + nCmdLineLenW + sizeof(PEPARAM);
		if (0 == VirtualQuery(pImageBase, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
			__leave;
		//HANDLE hmapping=CreateFileMapping(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0, nMemNead,NULL);
		//if(hmapping==NULL) return NULL;
		//LPVOID pImgBase=MapViewOfFileEx(hmapping,FILE_MAP_WRITE,0,0,0,pImageBase);
		//if(pImgBase==NULL) {
		//       pImgBase=MapViewOfFileEx(hmapping,FILE_MAP_WRITE,0,0,0,NULL);
		//}
		//CloseHandle(hmapping); 
		//if(pImageBase == NULL)
		//       return 0;
		//lpRelocPe = pImgBase;
		if ((MEM_FREE == mbi.State) && ((SIZE_T)nMemNead < mbi.RegionSize))
		{
			lpRelocPe = (HINSTANCE)VirtualAlloc(pImageBase, nMemNead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		}
		if (lpRelocPe == NULL)
		{
			lpRelocPe = (HINSTANCE)VirtualAlloc(NULL, nMemNead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (NULL == lpRelocPe)
			{
				nRet = ERROR_MEMLESS;
				__leave;
			}
		}
		lpPeBlock = (LPBYTE)lpRelocPe + nRawRelocPeImageSize;
		lpwCmdLine = LPWSTR((LPBYTE)lpPeBlock + nPeBlockImageSize);
		lpCmdLine = (LPSTR)((LPBYTE)lpwCmdLine + nCmdLineLenW);
		pPeParam = (LPPEPARAM)((LPBYTE)lpCmdLine + nCmdLineLenA);

		nRet = AlignPEToMem(lpRawRelocPe, lpRelocPe);
		if (nRet)
			__leave;
		nRet = AlignPEToMem(pRawPeBlock, lpPeBlock);
		if (nRet)
			__leave;
		if (lpRelocPe != pImageBase)
		{
			nRet = RelocatePe(lpRelocPe, 0, lpRelocPe);
			if (nRet)
				__leave;
		}

		nRet = FillImportTable(lpPeBlock);
		if (nRet)
			__leave;
		nRet = RelocatePe(lpPeBlock, 0, lpPeBlock);
		if (nRet)
			__leave;
		lstrcpyA(lpCmdLine, lpCommandLine);
		lstrcpyW(lpwCmdLine, lpwCommandLine);
		pPeParam->fSuicid = fSuicid;

		pDosHeader = (PIMAGE_DOS_HEADER)pRawPeBlock;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		FARPROC pEntryPoint = (FARPROC)((LPBYTE)lpPeBlock + (unsigned int)pNTHeader->OptionalHeader.AddressOfEntryPoint);
		DWORD dwThreadId;
		hRet = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pEntryPoint, lpRelocPe, 0, &dwThreadId);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		nRet = ERROR_UNKNOWN;
	}
	if (nRet)
	{
		if (lpRelocPe)
		{
			VirtualFree(lpRelocPe, 0, MEM_FREE);
			lpRelocPe = NULL;
			hRet = NULL;
		}
	}
	if (lpCommandLine)
		_free(lpCommandLine);
	if (phInst)
		*phInst = (HINSTANCE)lpRelocPe;
	if (fSuicid == FALSE)
		*pfUnload = (PROCUNLOAD)_GetProcAddress((HMODULE)lpPeBlock, pzUnLoad);
	return hRet;
}

HANDLE __stdcall LoadPeExA(DWORD dwProcessID, LPVOID lpRawRelocPe, LPCSTR lpCommandLine, HINSTANCE *phRemotInst, BOOL fSuicid, PROCUNLOAD *pfUnload)
{
	HANDLE hRet = NULL;
	int nCmdLineLen = lstrlenA(lpCommandLine) + 1;
	PWCHAR pwCmdLine = (PWCHAR)_malloc(nCmdLineLen * sizeof(WCHAR));
	if (MultiByteToWideChar(CP_THREAD_ACP, MB_COMPOSITE, lpCommandLine, -1, pwCmdLine, nCmdLineLen))
		hRet = LoadPeExW(dwProcessID, lpRawRelocPe, pwCmdLine, phRemotInst, fSuicid, pfUnload);
	_free(pwCmdLine);
	return hRet;
}

HANDLE __stdcall LoadPeExW(DWORD dwProcessID, LPVOID lpRawRelocPe, LPCWSTR lpwCommandLine, HINSTANCE *phRemotInst, BOOL fSuicid, PROCUNLOAD *pfUnload)
{
	HANDLE hRet = 0;
	int nRet = ERROR_UNKNOWN;
	int nPeBlockImageSize = 0;
	int nRawRelocPeImageSize = 0;
	int nCmdLineLenA = 0;
	int nCmdLineLenW = 0;
	UINT nMemNead = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	LPVOID pRelocPe = NULL;
	LPVOID pRemotRelocPe = NULL;
	LPVOID pPeBlock = NULL;
	LPVOID lpRemotePeBlock = NULL;
	LPSTR lpCommandLine = NULL;
	LPSTR  lpCmdLine = NULL;
	LPWSTR lpwCmdLine = NULL;
	LPPEPARAM pPeParam = NULL;
	//       LPWSTR lpwRemotCmdLine = NULL;
	LPVOID pRelocPeImageBase = NULL;
	__try
	{
		if (lpwCommandLine == NULL)
			__leave;
		nCmdLineLenA = lstrlenW(lpwCommandLine);
		nCmdLineLenA += sizeof(CHAR);
		nCmdLineLenW = lstrlenW(lpwCommandLine) * sizeof(WCHAR);
		nCmdLineLenW += sizeof(WCHAR);
		lpCommandLine = (LPSTR)_malloc(nCmdLineLenA);
		if (0 == WideCharToMultiByte(CP_THREAD_ACP, 0, lpwCommandLine, -1, lpCommandLine, nCmdLineLenA, NULL, NULL))
			__leave;

		nRet = VerifyPE(pRawPeBlock);
		if (nRet)
			__leave;
		nRet = VerifyPE(lpRawRelocPe);
		if (nRet)
			__leave;

		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
		if (hProcess == NULL)
		{
			nRet = ERROR_INVALID_OPENPROCESS;
			__leave;
		}
		pDosHeader = (PIMAGE_DOS_HEADER)pRawPeBlock;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) // the pRawPeBlock should not be a Dll
		{
			nRet = ERROR_INVALID_MEMPEBLOCK;
			__leave;
		}
		nPeBlockImageSize = pNTHeader->OptionalHeader.SizeOfImage;
		pDosHeader = (PIMAGE_DOS_HEADER)lpRawRelocPe;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		pRelocPeImageBase = (LPVOID)(ULONG_PTR)pNTHeader->OptionalHeader.ImageBase;
		nRawRelocPeImageSize = pNTHeader->OptionalHeader.SizeOfImage;
		nMemNead = nRawRelocPeImageSize + nPeBlockImageSize + nCmdLineLenA + nCmdLineLenW + sizeof(PEPARAM);
		if (0 == VirtualQueryEx(hProcess, pRelocPeImageBase, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
			__leave;
		if ((MEM_FREE == mbi.State) && ((SIZE_T)nMemNead < mbi.RegionSize))
			pRemotRelocPe = VirtualAllocEx(hProcess, pRelocPeImageBase, nMemNead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pRemotRelocPe == NULL)
		{
			pRemotRelocPe = VirtualAllocEx(hProcess, NULL, nMemNead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			VirtualQuery(pRemotRelocPe, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			if (NULL == pRemotRelocPe)
				__leave;
		}
		pRelocPe = VirtualAlloc(NULL, nMemNead, MEM_COMMIT, PAGE_READWRITE);
		pPeBlock = (LPBYTE)pRelocPe + nRawRelocPeImageSize;
		lpRemotePeBlock = (LPBYTE)pRemotRelocPe + nRawRelocPeImageSize;
		lpwCmdLine = LPWSTR((LPBYTE)pPeBlock + nPeBlockImageSize);
		lpCmdLine = LPSTR((LPBYTE)lpwCmdLine + nCmdLineLenW);
		pPeParam = LPPEPARAM((LPBYTE)lpCmdLine + nCmdLineLenA);
		//               lpwRemotCmdLine = LPWSTR((LPBYTE)lpRemotePeBlock + nPeBlockImageSize);
		nRet = AlignPEToMem(lpRawRelocPe, pRelocPe);
		if (nRet)
			__leave;
		nRet = AlignPEToMem(pRawPeBlock, pPeBlock);
		if (nRet)
			__leave;
		nRet = FillImportTable(pPeBlock);
		if (nRet)
			__leave;

		if (pRelocPeImageBase != pRemotRelocPe)
		{
			nRet = RelocatePe(pRelocPe, 0, pRemotRelocPe);
			if (nRet)
				__leave;
		}
		nRet = RelocatePe(pPeBlock, 0, lpRemotePeBlock);
		if (nRet)
			__leave;
		lstrcpyA(lpCmdLine, lpCommandLine);
		lstrcpyW(lpwCmdLine, lpwCommandLine);
		pPeParam->fSuicid = fSuicid;

		pDosHeader = (PIMAGE_DOS_HEADER)pRawPeBlock;
		pNTHeader = PIMAGE_NT_HEADERS((LPBYTE)pDosHeader + pDosHeader->e_lfanew);
		FARPROC pEntryPoint = (FARPROC)((LPBYTE)lpRemotePeBlock + pNTHeader->OptionalHeader.AddressOfEntryPoint);
		DWORD dwNumByteWrite = 0;
		if ((FALSE == WriteProcessMemory(hProcess, pRemotRelocPe, pRelocPe, nMemNead, &dwNumByteWrite)) || /
			(dwNumByteWrite != nMemNead))
		{
			nRet = ERROR_FAILED_WRITEMEMORY;
			__leave;
		}
		else
		{
			DWORD dwThreadId;
			hRet = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pEntryPoint, pRemotRelocPe, 0, &dwThreadId);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		nRet = ERROR_UNKNOWN;
	}
	if (nRet)
	{
		if (pRemotRelocPe)
		{
			VirtualFreeEx(hProcess, pRemotRelocPe, 0, MEM_FREE);
			pRemotRelocPe = NULL;
		}
	}
	if (pRelocPe)
		VirtualFree(pRelocPe, 0, MEM_FREE);
	if (hProcess)
		CloseHandle(hProcess);
	if (lpCommandLine)
		_free(lpCommandLine);
	if (phRemotInst)
		*phRemotInst = (HINSTANCE)pRemotRelocPe;
	if (fSuicid == FALSE)
	{
		FARPROC pfProc = _GetProcAddress((HMODULE)pPeBlock, pzUnLoad);
		*pfUnload = (PROCUNLOAD)((LPBYTE)lpRemotePeBlock + ((LPBYTE)pPeBlock - (LPBYTE)pfProc));
	}
	return hRet;
}

int __stdcall UnloadPe(PROCUNLOAD pFouncUnload)
{
	DWORD dwRet = 0;
	DWORD uThreadId;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pFouncUnload, 0, 0, &uThreadId);
	WaitForSingleObject(hThread, -1);
	if (0 == GetExitCodeThread(hThread, &dwRet))
	{
		dwRet = GetLastError();
	}
	return (int)dwRet;
}

int __stdcall UnloadPeEx(DWORD dwProcessID, PROCUNLOAD pProcUnload)
{
	int nRet = 0;
	DWORD uThreadId;
	HANDLE hProcess;
	HANDLE hThread;
	if (hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessID))
	{
		if (hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProcUnload, 0, 0, &uThreadId))
		{
			CloseHandle(hThread);
			nRet = GetLastError();
		}
		CloseHandle(hProcess);
	}
	else
	{
		nRet = GetLastError();
	}
	return nRet;
}

// Like GetProcAddress(), returns null if the procedure/ordinal is not there, otherwise returns function addr.
FARPROC __stdcall _GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	if ((hModule == NULL) || (lpProcName == NULL))
		return NULL;
	// Get header   
	PIMAGE_OPTIONAL_HEADER   poh;
	poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(hModule);

	// Get number of image directories in list
	int nDirCount;
	nDirCount = poh->NumberOfRvaAndSizes;
	if (nDirCount < 16)
		return NULL;

	// - Sift through export table -----------------------------------------------
	if (poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		return NULL;

	// Good, we have an export table. Lets get it.
	PIMAGE_EXPORT_DIRECTORY ped;
	ped = (IMAGE_EXPORT_DIRECTORY *)RVATOVA(hModule, poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Get ordinal of desired function
	int nOrdinal;

	if (HIWORD((DWORD)(ULONG_PTR)lpProcName) == 0) {
		nOrdinal = (LOWORD((DWORD)(ULONG_PTR)lpProcName)) - ped->Base;
	}
	else {

		// Go through name table and find appropriate ordinal

		int i, count;
		DWORD *pdwNamePtr;
		WORD *pwOrdinalPtr;

		count = ped->NumberOfNames;
		pdwNamePtr = (DWORD *)RVATOVA(hModule, ped->AddressOfNames);
		pwOrdinalPtr = (WORD *)RVATOVA(hModule, ped->AddressOfNameOrdinals);

		for (i = 0;i < count;i++) {

			// XXX should be a binary search, but, again, fuck it.
			char *svName;
			svName = (char *)RVATOVA(hModule, *pdwNamePtr);
			if (s_strcmpiA(svName, lpProcName) == 0) {
				nOrdinal = *pwOrdinalPtr;
				break;
			}
			pdwNamePtr++;
			pwOrdinalPtr++;
		}
		if (i == count)
			return NULL;
	}

	// Look up RVA of this ordinal
	DWORD *pAddrTable;
	DWORD dwRVA;
	pAddrTable = (DWORD *)RVATOVA(hModule, ped->AddressOfFunctions);

	dwRVA = pAddrTable[nOrdinal];

	// Check if it's a forwarder, or a local addr
	// XXX Should probably do this someday. Just don't define forwarders. You're
	// XXX not loading kernel32.dll with this shit anyway.

	FARPROC dwAddr;
	dwAddr = (FARPROC)RVATOVA(hModule, dwRVA);

	return dwAddr;
}

HINSTANCE __stdcall _LoadLibraryA(LPVOID lpRawRelocPe, LPCSTR lpLibFileName)
{
	return _LoadLibraryExA(lpRawRelocPe, lpLibFileName, NULL, 0);
}

HINSTANCE __stdcall _LoadLibraryW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName)
{
	return _LoadLibraryExW(lpRawRelocPe, lpLibFileName, NULL, 0);
}

HINSTANCE __stdcall _LoadLibraryExA(LPVOID lpRawRelocPe, LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HINSTANCE hRet = NULL;
	int nLibNameLen = lstrlenA(lpLibFileName) + 1;
	PWCHAR pwLibName = (PWCHAR)_malloc(nLibNameLen * sizeof(WCHAR));
	if (MultiByteToWideChar(CP_THREAD_ACP, MB_COMPOSITE, lpLibFileName, -1, pwLibName, nLibNameLen))
		hRet = _LoadLibraryExW(lpRawRelocPe, pwLibName, NULL, 0);
	_free(pwLibName);
	return hRet;
}

HINSTANCE __stdcall _LoadLibraryExW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HINSTANCE phInst;
	HANDLE hLib = LoadPeW(lpRawRelocPe, lpLibFileName, &phInst, FALSE, NULL);
	WaitForSingleObject(hLib, -1);
	return phInst;
}

BOOL      __stdcall       _FreeLibrary(HMODULE hLibModule)
{
	PROCUNLOAD pProcUnload;
	pProcUnload = (PROCUNLOAD)_GetProcAddress(hLibModule, pzUnLoad);
	DWORD dwRet = 0;
	DWORD uThreadId;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pProcUnload, 0, 0, &uThreadId);
	WaitForSingleObject(hThread, -1);
	if (0 == GetExitCodeThread(hThread, &dwRet))
	{
		dwRet = GetLastError();
	}
	return !dwRet;
}