#include <windows.h>
#include <wincodec.h>
#include <wchar.h>
#include <psapi.h>
#include <comdef.h>
#include <crtdbg.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sddl.h> 
#include <AclAPI.h> 
#include <Lmcons.h> 

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "psapi.lib")

bool g_advancedDebug = true;
std::wstring g_resultFile;

void PrintFileIntegrityLevel(const wchar_t* filePath);
void PrintFileOwner(const wchar_t* filePath);
void PrintProcessUser(HANDLE hProcess, const wchar_t* label);

void PrintError(const wchar_t* step, HRESULT hr) {
    _com_error err(hr);
    fwprintf(stderr, L"[!] %s failed. HRESULT = 0x%08X (%s)\n", step, hr, err.ErrorMessage());
}

void PrintProcessStats(const wchar_t* label) {
    PROCESS_MEMORY_COUNTERS_EX memInfo = {};
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&memInfo, sizeof(memInfo))) {
        wprintf(L"\n--- %s ---\n", label);
        wprintf(L"Working Set Size    : %llu KB\n", memInfo.WorkingSetSize / 1024);
        wprintf(L"Private Usage       : %llu KB\n", memInfo.PrivateUsage / 1024);
        wprintf(L"Pagefile Usage      : %llu KB\n", memInfo.PagefileUsage / 1024);
        wprintf(L"Peak Working Set    : %llu KB\n", memInfo.PeakWorkingSetSize / 1024);
        wprintf(L"Peak Pagefile Usage : %llu KB\n", memInfo.PeakPagefileUsage / 1024);
        wprintf(L"---------------------------\n");
    }
}

void PrintLoadedModules(const wchar_t* label) {
    wprintf(L"\n=== Loaded Modules: %s ===\n", label);
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                MODULEINFO modInfo = {};
                GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo));
                wprintf(L"  %s\n", szModName);
                wprintf(L"    [Base Address: %p] [Size: %lu bytes]\n", modInfo.lpBaseOfDll, modInfo.SizeOfImage);
                PrintFileIntegrityLevel(szModName);
                PrintFileOwner(szModName);
            }   
        }
    }
    wprintf(L"============================\n");
}

void PrintWICBasics() {
    wprintf(L"======================\n");
}

bool SafeCopyPixelsAndShowBytes(
    IWICBitmapFrameDecode* pFrame,
    UINT width,
    UINT height,
    REFWICPixelFormatGUID format,
    std::vector<BYTE>& outBuffer
) {
    UINT bpp = 0;
    IWICImagingFactory* pFactory = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pFactory)
    );
    if (FAILED(hr)) {
        PrintError(L"SafeCopyPixels: CoCreateInstance", hr);
        return false;
    }
    if (IsEqualGUID(format, GUID_WICPixelFormat32bppBGRA) ||
        IsEqualGUID(format, GUID_WICPixelFormat32bppRGBA)) {
        bpp = 32;
    } else if (IsEqualGUID(format, GUID_WICPixelFormat24bppBGR)) {
        bpp = 24;
    } else if (IsEqualGUID(format, GUID_WICPixelFormat8bppGray)) {
        bpp = 8;
    } else {
        bpp = 32;
    }
    pFactory->Release();
    UINT stride = (width * bpp + 7) / 8;
    UINT bufferSize = stride * height;
    const UINT MAX_IMAGE_SIZE = 16384;
    if (width > MAX_IMAGE_SIZE || height > MAX_IMAGE_SIZE) {
        wprintf(L"[!] Image dimensions too large, possible overflow: %ux%u\n", width, height);
        return false;
    }
    if (bufferSize == 0 || bufferSize > 512 * 1024 * 1024) {
        wprintf(L"[!] Buffer size too large or zero: %u bytes\n", bufferSize);
        return false;
    }
    outBuffer.resize(bufferSize, 0xCD);
    WICRect rc = { 0, 0, (INT)width, (INT)height };
    hr = pFrame->CopyPixels(&rc, stride, bufferSize, outBuffer.data());
    if (FAILED(hr)) {
        PrintError(L"CopyPixels", hr);
        return false;
    }
    bool overrun = false;
    for (size_t i = bufferSize; i < outBuffer.size(); ++i) {
        if (outBuffer[i] != 0xCD) {
            overrun = true;
            break;
        }
    }
    if (overrun) {
        wprintf(L"[!] Buffer overrun detected after CopyPixels!\n");
        return false;
    }
    wprintf(L"[+] CopyPixels completed safely. Buffer size: %u bytes\n", bufferSize);

    
    const size_t numBytesToShow = 16;
    size_t start = (bufferSize > numBytesToShow) ? bufferSize - numBytesToShow : 0;
    wprintf(L"Final %zu bytes (hex): ", numBytesToShow);
    for (size_t i = start; i < bufferSize; ++i) {
        wprintf(L"%02X ", outBuffer[i]);
    }
    wprintf(L"\nFinal %zu bytes (ASCII): ", numBytesToShow);
    for (size_t i = start; i < bufferSize; ++i) {
        char c = (outBuffer[i] >= 32 && outBuffer[i] <= 126) ? (char)outBuffer[i] : '.';
        wprintf(L"%c", c);
    }
    wprintf(L"\n");

    return true;
}

void PrintProcessIntegrityLevel(HANDLE hProcess, const wchar_t* label) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return;
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return;
    }
    std::vector<BYTE> buffer(dwLength);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer.data(), dwLength, &dwLength)) {
        CloseHandle(hToken);
        return;
    }
    PTOKEN_MANDATORY_LABEL pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());
    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
        static_cast<DWORD>(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
    const wchar_t* level = L"Unknown";
    if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
        level = L"Low";
    else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
        level = L"Medium";
    else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
        level = L"High";
    else
        level = L"System";
    wprintf(L"Process Integrity Level (%s): %s\n", label, level);
    CloseHandle(hToken);
}

void PrintFileIntegrityLevel(const wchar_t* filePath) {
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (GetNamedSecurityInfoW(filePath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &pSD) == ERROR_SUCCESS && pSD) {
        PACL pSacl = nullptr;
        BOOL fSaclPresent = FALSE, fSaclDefaulted = FALSE;
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted) && fSaclPresent && pSacl) {
            for (DWORD i = 0; i < pSacl->AceCount; ++i) {
                PACE_HEADER pAceHeader = nullptr;
                if (GetAce(pSacl, i, (LPVOID*)&pAceHeader) && pAceHeader->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                    PSYSTEM_MANDATORY_LABEL_ACE pLabelAce = (PSYSTEM_MANDATORY_LABEL_ACE)pAceHeader;
                    DWORD dwIntegrityLevel = *GetSidSubAuthority(&pLabelAce->SidStart,
                        static_cast<DWORD>(*GetSidSubAuthorityCount(&pLabelAce->SidStart) - 1));
                    const wchar_t* level = L"Unknown";
                    if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
                        level = L"Low";
                    else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                        level = L"Medium";
                    else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                        level = L"High";
                    else
                        level = L"System";
                    wprintf(L"    [File Integrity Level: %s]\n", level);
                    break;
                }
            }
        }
        LocalFree(pSD);
    }
}

void PrintFileOwner(const wchar_t* filePath) {
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PSID pOwner = nullptr;
    BOOL ownerDefaulted = FALSE;
    if (GetNamedSecurityInfoW(filePath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
        &pOwner, nullptr, nullptr, nullptr, &pSD) == ERROR_SUCCESS && pOwner) {
        wchar_t name[UNLEN + 1] = L"";
        wchar_t domain[GNLEN + 1] = L"";
        DWORD nameLen = UNLEN, domainLen = GNLEN;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, pOwner, name, &nameLen, domain, &domainLen, &use)) {
            wprintf(L"    [File Owner: %s\\%s]\n", domain, name);
        } else {
            wprintf(L"    [File Owner: (unknown)]\n");
        }
        LocalFree(pSD);
    } else {
        wprintf(L"    [File Owner: (unavailable)]\n");
    }
}

void PrintProcessUser(HANDLE hProcess, const wchar_t* label) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return;
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return;
    }
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(hToken);
        return;
    }
    PTOKEN_USER pUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
    wchar_t name[UNLEN + 1] = L"";
    wchar_t domain[GNLEN + 1] = L"";
    DWORD nameLen = UNLEN, domainLen = GNLEN;
    SID_NAME_USE use;
    if (LookupAccountSidW(nullptr, pUser->User.Sid, name, &nameLen, domain, &domainLen, &use)) {
        wprintf(L"Process User (%s): %s\\%s\n", label, domain, name);
    } else {
        wprintf(L"Process User (%s): (unknown)\n", label);
    }
    CloseHandle(hToken);
}

void SaveResult(bool success) {
    if (!g_resultFile.empty()) {
        std::wofstream ofs(g_resultFile, std::ios::trunc);
        if (ofs) {
            ofs << (success ? L"success" : L"failure");
        }
    }
}

bool IsImageSafe(UINT width, UINT height, UINT bufferSize, bool copySuccess) {
    if (!copySuccess) return false;
    if (width == 0 || height == 0) return false;
    if (width > 16384 || height > 16384) return false;
    if (bufferSize == 0 || bufferSize > 512 * 1024 * 1024) return false;
    return true;
}

int wmain(int argc, wchar_t* argv[])
{
#if defined(_DEBUG)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    g_advancedDebug = true;
    bool saveResultOnly = false;
    g_resultFile.clear();

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--basic") == 0) {
            g_advancedDebug = false;
        }
        if (wcscmp(argv[i], L"--resultfile") == 0 && i + 1 < argc) {
            g_advancedDebug = false;
            saveResultOnly = true;
            g_resultFile = argv[i + 1];
            ++i;
        }
    }

    if (argc < 2 || (argc == 2 && (g_advancedDebug == false || saveResultOnly))) {
        fwprintf(stderr, L"Usage: %s <image-file-path> [--basic] [--resultfile <file>]\n", argv[0]);
        return -1;
    }

    const wchar_t* imagePath = argv[1];
    bool success = true;
    bool imageSafe = false;
    UINT width = 0, height = 0, bufferSize = 0;
    std::vector<BYTE> imageBuffer;

    const wchar_t* filesToCheck[] = {
        L"C:\\WINDOWS\\SYSTEM32\\ntdll.dll",
        L"C:\\WINDOWS\\System32\\KERNEL32.DLL",
        L"C:\\WINDOWS\\System32\\KERNELBASE.dll",
        L"C:\\WINDOWS\\System32\\ADVAPI32.dll",
        L"C:\\WINDOWS\\System32\\msvcrt.dll",
        L"C:\\WINDOWS\\System32\\sechost.dll",
        L"C:\\WINDOWS\\System32\\RPCRT4.dll",
        L"C:\\WINDOWS\\System32\\ole32.dll",
        L"C:\\WINDOWS\\System32\\msvcp_win.dll",
        L"C:\\WINDOWS\\System32\\ucrtbase.dll",
        L"C:\\WINDOWS\\System32\\GDI32.dll",
        L"C:\\WINDOWS\\System32\\win32u.dll",
        L"C:\\WINDOWS\\System32\\gdi32full.dll",
        L"C:\\WINDOWS\\System32\\USER32.dll",
        L"C:\\WINDOWS\\System32\\combase.dll",
        L"C:\\WINDOWS\\SYSTEM32\\VCRUNTIME140D.dll",
        L"C:\\WINDOWS\\SYSTEM32\\VCRUNTIME140_1D.dll",
        L"C:\\WINDOWS\\SYSTEM32\\MSVCP140D.dll",
        L"C:\\WINDOWS\\SYSTEM32\\ucrtbased.dll",
        L"C:\\WINDOWS\\System32\\IMM32.DLL",
        L"C:\\WINDOWS\\SYSTEM32\\ntmarta.dll"
    };

    if (g_advancedDebug) {
        wprintf(L"[+] Opening image: %s\n", imagePath);
        wprintf(L"Process ID: %lu\n", GetCurrentProcessId());
        wprintf(L"Thread ID: %lu\n", GetCurrentThreadId());
        PrintProcessIntegrityLevel(GetCurrentProcess(), L"Startup");
        PrintProcessUser(GetCurrentProcess(), L"Startup");
        PrintFileIntegrityLevel(imagePath);
        PrintFileOwner(imagePath);
        PrintLoadedModules(L"Before COM Init");
        PrintProcessStats(L"Before COM Init");

        wprintf(L"\n=== Integrity Level for Key Files ===\n");
        for (const auto& file : filesToCheck) {
            wprintf(L"%s\n", file);
            PrintFileIntegrityLevel(file);
            PrintFileOwner(file);
        }
        wprintf(L"====================================\n");
    }

    
    HRESULT hr = S_OK;
    IWICImagingFactory* pFactory = nullptr;
    IWICBitmapDecoder* pDecoder = nullptr;
    IWICBitmapFrameDecode* pFrame = nullptr;
    WICPixelFormatGUID format = {};
    UINT bpp = 32;
    UINT stride = 0;
    bool copySuccess = false;

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CoInitializeEx", hr);
        success = false;
        SaveResult(success);
        if (!g_advancedDebug) wprintf(L"failure\n");
        goto show_final_bytes_and_exit;
    }

    hr = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pFactory)
    );
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CoCreateInstance (WICImagingFactory)", hr);
        goto show_final_bytes_and_exit;
    }

    hr = pFactory->CreateDecoderFromFilename(
        imagePath,
        nullptr,
        GENERIC_READ,
        WICDecodeMetadataCacheOnLoad,
        &pDecoder
    );
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CreateDecoderFromFilename", hr);
        goto show_final_bytes_and_exit;
    }

    hr = pDecoder->GetFrame(0, &pFrame);
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"GetFrame(0)", hr);
        goto show_final_bytes_and_exit;
    }

    hr = pFrame->GetSize(&width, &height);
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"GetSize", hr);
        goto show_final_bytes_and_exit;
    }

    hr = pFrame->GetPixelFormat(&format);
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"GetPixelFormat", hr);
        goto show_final_bytes_and_exit;
    }

    if (IsEqualGUID(format, GUID_WICPixelFormat32bppBGRA) ||
        IsEqualGUID(format, GUID_WICPixelFormat32bppRGBA)) {
        bpp = 32;
    } else if (IsEqualGUID(format, GUID_WICPixelFormat24bppBGR)) {
        bpp = 24;
    } else if (IsEqualGUID(format, GUID_WICPixelFormat8bppGray)) {
        bpp = 8;
    }
    stride = (width * bpp + 7) / 8;
    bufferSize = stride * height;

    copySuccess = SafeCopyPixelsAndShowBytes(pFrame, width, height, format, imageBuffer);
    imageSafe = IsImageSafe(width, height, bufferSize, copySuccess);

    if (!copySuccess) {
        success = false;
        SaveResult(success);
        if (!g_advancedDebug) wprintf(L"failure\n");
        goto show_final_bytes_and_exit;
    }

show_final_bytes_and_exit:
    if (pFrame) pFrame->Release();
    if (pDecoder) pDecoder->Release();
    if (pFactory) pFactory->Release();
    CoUninitialize();

    if (!imageBuffer.empty()) {
        const size_t numBytesToShow = 16;
        size_t bufferSize = imageBuffer.size();
        size_t start = (bufferSize > numBytesToShow) ? bufferSize - numBytesToShow : 0;
        wprintf(L"\nFinal %zu bytes read (hex): ", numBytesToShow);
        for (size_t i = start; i < bufferSize; ++i) {
            wprintf(L"%02X ", imageBuffer[i]);
        }
        wprintf(L"\nFinal %zu bytes read (ASCII): ", numBytesToShow);
        for (size_t i = start; i < bufferSize; ++i) {
            char c = (imageBuffer[i] >= 32 && imageBuffer[i] <= 126) ? (char)imageBuffer[i] : '.';
            wprintf(L"%c", c);
        }
        wprintf(L"\n");
    }

    if (g_advancedDebug) {
        PrintLoadedModules(L"After COM Uninit");
        PrintProcessStats(L"After COM Uninit");
        if (imageSafe) {
            wprintf(L"[+] The image can be safely displayed.\n");
        } else {
            wprintf(L"[!] Security concern: The image may not be safe to display.\n");
        }
    } else {
        if (imageSafe) {
            wprintf(L"success\n");
        } else {
            wprintf(L"security concern\n");
        }
    }

    SaveResult(success);
    return 0;
}
