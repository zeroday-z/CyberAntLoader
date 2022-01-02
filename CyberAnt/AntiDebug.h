#include <Windows.h>
#include <iostream>
#include <string>
#include <ctime>
#include <fstream>
#include <iterator>
#include <comdef.h>
#include <VersionHelpers.h>
#include <atlstr.h>
#include <sstream>
#include <vector>
#include <psapi.h>

namespace AntiDebug
{
	extern inline BOOL IsDebuggerPresentAPI();
	extern inline BOOL CheckRemoteDebuggerPresentAPI();
	extern inline bool HideThread(HANDLE hThread);;
	extern inline BOOL HardwareBreakpoints();
	extern inline BOOL MemoryBreakpoints_PageGuard();
	extern inline BOOL ModuleBoundsHookCheck();
	extern inline BOOL UnhandledExcepFilterTest();
	extern inline BOOL SharedUserData_KernelDebugger();
	extern inline BOOL IsSystemCodeIntegrityEnabled();
	extern inline BOOL IsVM();
	extern inline BOOL IsSandboxie();
	extern inline BOOL IsVirtualBox();
}
