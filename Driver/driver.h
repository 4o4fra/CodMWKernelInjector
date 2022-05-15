#pragma once
#include <Windows.h>
#include <string>
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(default : 4005)
#include "defines.h"

class DriverClass
{
public:
	DriverClass();
	~DriverClass();

	DWORD ProcID = 0;

	static   DriverClass& singleton();
	void     DriverHANDLE();
	void     AttachToProcess(DWORD pid);

	NTSTATUS send_serivce(ULONG ioctl_code, LPVOID io, DWORD size);
	NTSTATUS get_module_information_ex(const wchar_t* name, pget_module_information mod);
	NTSTATUS read_memory_ex(PVOID base, PVOID buffer, DWORD size);
	NTSTATUS write_memory_ex(PVOID base, PVOID buffer, DWORD size);
	NTSTATUS protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection);
	PVOID    alloc_memory_ex(DWORD size, DWORD protect);
	NTSTATUS free_memory_ex(PVOID address);
	
	inline bool isLoaded()  const { return DRIVERHANDLE != INVALID_HANDLE_VALUE; }
private:	
	DriverClass(const DriverClass&) = delete;
	DriverClass& operator = (const DriverClass&) = delete;
	HANDLE   DRIVERHANDLE = INVALID_HANDLE_VALUE;
};

inline DriverClass& DRV()
{
	return DriverClass::singleton();
}



