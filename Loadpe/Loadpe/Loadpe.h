// LoadPe.h
#pragma once

// 在内存中加载PE文件（主要支持EXE，DLL以及由之衍生的OCX，AX等）
// 最原始的代码参见Bo2000中dll_load.cpp。
// 要求：
//               推荐带重定位信息，否则对于多数Pe文件是无法成功加载的。
// 注意：
//               仅在本人机器上测试，环境：CPU: Celeron 1.7G Memory: 256M OS:WinXp sp2 Complier: VC++6.0 Editor: VS2005
//               支持Win2000,WinXp,Win2003,WinVista; 
//               不支持WinMe,Win98,Win95以及更早的Windows产品
// 限制：
//               Commandline 应该是"ModuleFileName Param1 param2 ...", 如果ModuleFileName为空，GetModuleFileName将返回空，这对于多数程序是无法接受的。
//               不支持通过间接途径或通过函数序号调用GetModuleHandle,GetModuleFileName,GetCommandLine且依赖这些函数其返回值的Pe文件。
//               对于MFC程序,ModuleFileName必须带有"."(参看MFC源代码AppInit.cpp中CWinApp::SetCurrentHandles()函数，要求文件名中必须有"."的存在，比如"my.dll", "my.", ".my"都合法)。
//               不支持动态链接的MFC程序(原因是在动态链接MFC库的程序中GetModuleHandle,GetModuleFileName,GetCommandLine是在MFC*.dll中调用,违反上述限制)。
// 如何正确地使用：
//               fSuicid是一个必须仔细考虑的一个标志：
//                        设定了fSuicid,且Pe文件是多线程的，则应该保证ExeEntry或DllEntry是最后一个返回的线程，否则会卸载仍有活动线程的内存区域，导致线程访问已卸载的内存空间而出错。
//                        带apiHook目的的Pe不应该指定fSuicid=TRUE;


#ifdef __cplusplus
extern "C" {
#endif
	typedef int(__stdcall *PROCUNLOAD)(int uExitCode);
	HINSTANCE __stdcall _LoadLibraryA(LPVOID lpRawRelocPe, LPCSTR lpLibFileName);
	HINSTANCE __stdcall _LoadLibraryW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName);
	HINSTANCE __stdcall _LoadLibraryExA(LPVOID lpRawRelocPe, LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	HINSTANCE __stdcall _LoadLibraryExW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	BOOL      __stdcall _FreeLibrary(HMODULE hLibModule);



	HANDLE __stdcall LoadPeA(LPVOID lpRawRelocPe, LPCSTR lpCommandLine, HINSTANCE *phInst = NULL, BOOL fSuicid = FALSE, PROCUNLOAD *pfUnload = NULL); // if fSuicid is FASLE, the pfUnload should NOT be NULL;
	HANDLE __stdcall LoadPeW(LPVOID lpRawRelocPe, LPCWSTR lpwCommandLine, HINSTANCE *phInst = NULL, BOOL fSuicid = FALSE, PROCUNLOAD *pfUnload = NULL);
	HANDLE __stdcall LoadPeExA(DWORD dwProcessID, LPVOID lpRawRelocPe, LPCSTR lpCommandLine, HINSTANCE *phRemotInst = NULL, BOOL fSuicid = FALSE, PROCUNLOAD *pfUnload = NULL);
	HANDLE __stdcall LoadPeExW(DWORD dwProcessID, LPVOID lpRawRelocPe, LPCWSTR lpwCommandLine, HINSTANCE *phRemotInst = NULL, BOOL fSuicid = FALSE, PROCUNLOAD *pfUnload = NULL);

	int __stdcall UnloadPe(PROCUNLOAD pFouncUnload);
	int __stdcall UnloadPeEx(DWORD dwProcessID, PROCUNLOAD pFouncUnload);

	FARPROC __stdcall _GetProcAddress(HMODULE hModule, LPCSTR FuncName);

#ifdef __cplusplus
}

#endif



#ifdef UNICODE

#define LoadPe LoadPeW

#define LoadPeEx LoadPeExW

#else

#define LoadPe LoadPeA

#define LoadPeEx LoadPeExA

#endif