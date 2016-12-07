#if !defined(_RAWPEAPI__h_)
#define _RAWPEAPI__h_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#if (_MSC_VER < 1299)
typedef LONG LONG_PTR;
typedef ULONG ULONG_PTR;
#endif // _MSC_VER < 1299

#ifdef __cplusplus
extern "C" {

#endif
	struct FAKEPROC
	{

		LPCSTR  pProcName;
		FARPROC pFakeProc;

	};
	struct SENCEMODULE
	{

		LPCSTR pModuleName;
		FAKEPROC *pFakeProc;

	};
	// enmulate the windows Dynamic-Link Library Functions, and just load directely from memory
	HINSTANCE __stdcall _LoadLibraryA(LPVOID lpRawRelocPe, LPCSTR  lpLibFileName);
	HINSTANCE __stdcall _LoadLibraryW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName);
	HINSTANCE __stdcall _LoadLibraryExA(LPVOID lpRawRelocPe, LPCSTR  lpLibFileName, HANDLE hFile, DWORD dwFlags);
	HINSTANCE __stdcall _LoadLibraryExW(LPVOID lpRawRelocPe, LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	BOOL  __stdcall_FreeLibrary(HMODULE hLibModule);
	FARPROC  __stdcall _GetProcAddress(HMODULE hModule, LPCSTR FuncName);

	/* the core loader functions*/
	// LoadPe() functions
	HINSTANCE __stdcall LoadPeA(LPVOID lpRawRelocPe, LPCSTR lpCommandLineA, UINT uFlags, HANDLE *lphThread);
	HINSTANCE __stdcall LoadPeW(LPVOID lpRawRelocPe, LPCWSTR lpCommandLineW, UINT uFlags, HANDLE *lphThread);
	// LoadPeEx() function will execute an pe buffer in assign whether or not the LOAD_EXECUTE assine, 
	HINSTANCE __stdcall LoadPeExA(DWORD dwProcessId, LPVOID lpRawRelocPe, LPCSTR lpCommandLineA, UINT uFlags, HANDLE *lphThread);
	HINSTANCE __stdcall LoadPeExW(DWORD dwProcessId, LPVOID lpRawRelocPe, LPCWSTR lpCommandLineW, UINT uFlags, HANDLE *lphThread);
	// GetPeType just return TYPE_EXE , TYPE_DLL, or 0 for not support format pe.
	UINT  __stdcall GetPeType(LPVOID hInstance);
	// align all the raw pe, the PeBlock, the commandlines and the uFlags to the memory.
	int  __stdcall PrepareImage(LPVOID pMemImage, UINT nMemImageSize, LPVOID lpRawRelocPe, LPVOID lpRawPeBlock, LPCWSTR lpCommandLineW, UINT uFlags, LPVOID *lppPeBlock);
	// detective the operatoin system wheather a nt kernel
	BOOL  __stdcall IsNT();
	// spread the pe file follow the section align propertie to the memory
	int      __stdcall AlignPeToMem(LPVOID lpMemory, LPVOID lpRawPe);
	// verify the target Pe file whether support
	int  __stdcall VerifyPE(LPVOID hInst);
	// fill the import table
	int      __stdcall FillImportTable(LPVOID lpInstance);
	// relocate the target pe
	int       __stdcall RelocatePe(LPVOID hInst, LPVOID pOldBase, LPVOID pNewBase);
	// replace the api with customme fuction
	int  __stdcall ReplaceImpportAPI(LPVOID phInst, FARPROC fpOldProc, FARPROC fpNewProc);
	int  __stdcall ReplaceExpportAPI(LPVOID phInst, FARPROC fpOldProc, FARPROC fpNewProc);
	int  __stdcall SetImpportAPI(LPVOID phInst, LPCSTR lpModuleName, LPCSTR lpProcName, FARPROC fpAddr);
	// get a execute file image size
	int  __stdcall _GetImageSize(LPVOID lpRawPe);
	// resume the pe file's section protection propertie to the original statement
	INT  __stdcall ResumeMemState(LPVOID hInst);
	// get the section align size
	ULONG     __stdcall GetAlignedSize(ULONG Origin, ULONG Alignment);

	// the follow s_strcmpXXX() is used to saftly compare string or original
	ULONG_PTR __stdcall s_strcmpA(LPCSTR  lpName1, LPCSTR  lpName2);
	ULONG_PTR __stdcall s_strcmpW(LPCWSTR lpName1, LPCWSTR lpName2);
	ULONG_PTR __stdcall s_strcmpiA(LPCSTR  lpName1, LPCSTR  lpName2);
	ULONG_PTR __stdcall s_strcmpiW(LPCWSTR lpName1, LPCWSTR lpName2);

	typedef UINT(__stdcall *LPDLLENTRY)(HANDLE hInstance, DWORD Reason, LPVOID Reserved);
	typedef UINT(__cdecl   *LPEXEENTRY)(LPVOID lpParam);

#ifdef __cplusplus

}
#endif

#define ERROR_CUSTOM(~(UINT(-1) >> 1))
#define ERROR_INVALID_PEFORMAT(ERROR_CUSTOM + 0x00000001)
#define ERROR_INVALID_IMAGESIZE(ERROR_CUSTOM + 0x00000002)
#define ERROR_INVALID_MEMPEBLOCK(ERROR_CUSTOM + 0x00000003)
#define ERROR_INVALID_OPENPROCESS(ERROR_CUSTOM + 0x00000004)
#define ERROR_INVALID_PARAM(ERROR_CUSTOM + 0x00000006)
#define ERROR_NOTSUPPORT_PEFORMAT(ERROR_CUSTOM + 0x00000005)
#define ERROR_NOTSUPPORT_RELOC(ERROR_CUSTOM + 0x00000006)
#define ERROR_FAILED_RELOC(ERROR_CUSTOM + 0x00000010)
#define ERROR_FAILED_UNLOAD(ERROR_CUSTOM + 0x00000011)
#define ERROR_FAILED_LOADDLL(ERROR_CUSTOM + 0x00000012)
#define ERROR_FAILED_FUNCADDR(ERROR_CUSTOM + 0x00000013)
#define ERROR_FAILED_WRITEMEMORY(ERROR_CUSTOM + 0x00000014)
#define ERROR_FAILED_CREATEREOMTETHREAD(ERROR_CUSTOM + 0x00000015)
#define ERROR_NORELOC(ERROR_CUSTOM + 0x00000020)
#define ERROR_NOEXPORT(ERROR_CUSTOM + 0x00000021)
#define ERROR_NOTINIT(ERROR_CUSTOM + 0x00000030)
#define ERROR_MEMORYLESS(ERROR_CUSTOM + 0x00000040)
#define ERROR_NOCMDLINE(ERROR_CUSTOM + 0x00000050)
#define ERROR_NOTFOUND(ERROR_CUSTOM + 0x00000060)
#define ERROR_NOMODULENAME(ERROR_CUSTOM + 0x00000070)
#define ERROR_MEMLESS(ERROR_CUSTOM + 0x00000080)
#define ERROR_DATADIRS(ERROR_CUSTOM + 0x00000090)
#define ERROR_UNKNOWN(-1)

#define LOAD_EXECUTE(~(UINT(-1) >> 1)) 
#define LOAD_LIBRARY0 // only effect for native Process
#define LOAD_NEWTHREAD(LOAD_EXECUTE >> 1)  // 
#define LOAD_SUCISIDE(LOAD_EXECUTE >> 2)  // only use with LOAD_NEWTHREAD

#define TYPE_NOTSUPPORT0x00000000
#define TYPE_EXE0x00000010
#define TYPE_EXE_CUI0x00000011
#define TYPE_EXE_GUI0x00000012
#define TYPE_DLL0x00000020

#define RVATOVA(base, offset) ((LPVOID)((LPBYTE)(base)   + (DWORD)(offset)))
#define VATORVA(base, offset) ((LPVOID)((LPBYTE)(offset) - (DWORD)(base)))

#ifdef UNICODE
#define _LoadLibrary_LoadLibraryW
#define _LoadLibraryEx_LoadLibraryExW
#define LoadPeExLoadPeExW
#define LoadPeLoadPeW
#else
#define _LoadLibrary_LoadLibraryA
#define _LoadLibraryEx_LoadLibraryExA
#define LoadPeLoadPeA
#define LoadPeExLoadPeExA
#endif

#endif // defined(_RAWPEAPI__h_)

#if (_MSC_VER < 1299) // for VC6.0

#ifdef _DEBUG
#pragma comment(lib, "../lib/PeloaderD6.lib")
#else
#pragma comment(lib, "../lib/PeloaderR6.lib")
#endif

#else

#ifdef _DEBUG
#pragma comment(lib, "../lib/PeloaderD8.lib")
#else
#pragma comment(lib, "../lib/PeloaderR8.lib")
#endif

#endif // _MSC_VER < 1299
