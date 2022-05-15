#include "driver.h"
#include "../Communication/xor.h"

#define DVR_DEVICE_FILE xor_w(L"\\\\.\\EIQDV") 

DriverClass::DriverClass()
{
/**/
}
NTSTATUS DriverClass::send_serivce(ULONG ioctl_code, LPVOID io, DWORD size)
{
	if (DRIVERHANDLE == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;

	if (!DeviceIoControl(DRIVERHANDLE, ioctl_code, io, size, nullptr, 0, NULL, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
void DriverClass::AttachToProcess(DWORD pid)
{
	ProcID = pid;
}
NTSTATUS DriverClass::get_module_information_ex(const wchar_t* name, pget_module_information mod)
{
	if (DRIVERHANDLE == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;
	
	set_module_information req = { 0 };

	req.pid = ProcID;
	wcscpy_s(req.sz_name, name);

	if (!DeviceIoControl(DRIVERHANDLE, ioctl_get_module_information, &req, sizeof(req), mod, sizeof(get_module_information), 0, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
NTSTATUS DriverClass::read_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	copy_memory req = { 0 };

	req.pid = ProcID;
	req.address = reinterpret_cast<ULONGLONG>(base);
	req.buffer = reinterpret_cast<ULONGLONG>(buffer);
	req.size = (uint64_t)size;
	req.write = FALSE;

	return send_serivce(ioctl_copy_memory, &req, sizeof(req));
}
NTSTATUS DriverClass::write_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	copy_memory Request = { 0 };

	Request.pid = ProcID;
	Request.address = reinterpret_cast<ULONGLONG>(base);
	Request.buffer = reinterpret_cast<ULONGLONG>(buffer);
	Request.size = (uint64_t)size;
	Request.write = TRUE;

	return send_serivce(ioctl_copy_memory, &Request, sizeof(Request));
}
NTSTATUS DriverClass::protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection)
{
	protect_memory Request = { 0 };

	Request.pid = ProcID;
	Request.address = base;
	Request.size = size;
	Request.new_protect = protection;

	return send_serivce(ioctl_protect_memory, &Request, sizeof(Request));
}
PVOID DriverClass::alloc_memory_ex(DWORD size, DWORD protect)
{
	PVOID p_out_address = NULL;
	alloc_memory req = { 0 };

	req.pid = ProcID;
	req.out_address = reinterpret_cast<ULONGLONG>(&p_out_address);
	req.size = size;
	req.protect = protect;

	send_serivce(ioctl_alloc_memory, &req, sizeof(req));

	return p_out_address;
}
NTSTATUS DriverClass::free_memory_ex(PVOID address)
{
	free_memory req = { 0 };

	req.pid = ProcID;
	req.address = reinterpret_cast<ULONGLONG>(address);

	return send_serivce(ioctl_free_memory, &req, sizeof(req));
}
void DriverClass::DriverHANDLE()
{
	DRIVERHANDLE = CreateFileW(DVR_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}
DriverClass::~DriverClass()
{
	CloseHandle(DRIVERHANDLE);
}
DriverClass& DriverClass::singleton()
{
	static DriverClass p_object;
	return p_object;
}