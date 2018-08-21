#define WIN32_LEAN_AND_MEAN
#define _ATL_NO_AUTOMATIC_NAMESPACE
#include <windows.h>
#include <atlbase.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstdio>
#include <cstdlib>
#pragma comment(lib, "ntdll")

#include <system_error>

#ifndef FILE_CS_FLAG_CASE_SENSITIVE_DIR

#define FileCaseSensitiveInformation (FILE_INFORMATION_CLASS)71
#define FILE_CS_FLAG_CASE_SENSITIVE_DIR 0x00000001

typedef struct {
	ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

#endif

extern "C" NTSTATUS NTSYSAPI NTAPI NtSetInformationFile(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_In_  PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass);

int __cdecl wmain(int, PWSTR argv[])
{
	ATL::CHandle d(CreateFileW(argv[1], FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
	if (d == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile %08lx\n", GetLastError());
		d.Detach();
		return EXIT_FAILURE;
	}
	//int val = FILE_CS_FLAG_CASE_SENSITIVE_DIR & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR;
	IO_STATUS_BLOCK iob;
	FILE_CASE_SENSITIVE_INFORMATION file_cs = { 0 };// FILE_CS_FLAG_CASE_SENSITIVE_DIR

	NTSTATUS status = NtSetInformationFile(d, &iob, &file_cs, sizeof file_cs, FileCaseSensitiveInformation);
	if (NT_ERROR(status))
	{
		const auto err = ::RtlNtStatusToDosError(status);

		printf("NtSetInformationFile failed: %s\n", std::system_category().message(err).c_str());
		return EXIT_FAILURE;
	}
}