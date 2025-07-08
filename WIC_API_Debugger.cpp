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

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "psapi.lib")

bool g_advancedDebug = true;
std::wstring g_resultFile;


void TrackSubCall(const char* lib, const char* sublib, const char* func) {
    if (g_advancedDebug) {
        printf("[TRACK] %s/%s::%s\n", lib, sublib, func);
    }
}

void PrintError(const wchar_t* step, HRESULT hr) {
    _com_error err(hr);
    fwprintf(stderr, L"[!] %s failed. HRESULT = 0x%08X (%s)\n", step, hr, err.ErrorMessage());
}

void PrintMemoryUsage(const wchar_t* label) {
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
                wprintf(L"  %s\n", szModName);
            }
        }
    }
    wprintf(L"============================\n");
}

void PrintWICBasics() {
    wprintf(L"\n=== WIC API Basics ===\n");
    wprintf(L"- Windows Imaging Component (WIC) provides image decoding/encoding.\n");
    wprintf(L"- Use WIC for loading, saving, and processing images in various formats.\n");
    wprintf(L"======================\n");
}

void PrintWICWeaknesses() {
    wprintf(L"\n=== WIC API Weaknesses (General) ===\n");
    wprintf(L"- WIC does not validate all image metadata; malformed/corrupt files may cause undefined behavior.\n");
    wprintf(L"- WIC decoders may not check for integer overflows in extremely large images.\n");
    wprintf(L"- Always validate image dimensions and buffer sizes before allocating or copying pixel data.\n");
    wprintf(L"- Use SUCCEEDED/FAILED checks for all WIC API calls to avoid silent failures.\n");
    wprintf(L"- Avoid trusting image metadata for buffer allocations; check for reasonable limits.\n");
    wprintf(L"====================================\n");
}

#if defined(_DEBUG)
void DumpMemoryStats(const char* label) {
    _CrtMemState memState;
    _CrtMemCheckpoint(&memState);
    printf("\n==== CRT Memory Stats: %s ====\n", label);
    _CrtMemDumpStatistics(&memState);
    printf("================================\n");
}
#else
void DumpMemoryStats(const char*) {}
#endif

bool SafeCopyPixels(IWICBitmapFrameDecode* pFrame, UINT width, UINT height, REFWICPixelFormatGUID format) {
    UINT bpp = 0;
    IWICImagingFactory* pFactory = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pFactory)
    );
    TrackSubCall("wincodec", "ole32", "CoCreateInstance");
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
    std::vector<BYTE> buffer(bufferSize, 0xCD);
    WICRect rc = { 0, 0, (INT)width, (INT)height };
    hr = pFrame->CopyPixels(&rc, stride, bufferSize, buffer.data());
    TrackSubCall("wincodec", "wincodec", "CopyPixels");
    if (FAILED(hr)) {
        PrintError(L"CopyPixels", hr);
        return false;
    }
    bool overrun = false;
    for (size_t i = bufferSize; i < buffer.size(); ++i) {
        if (buffer[i] != 0xCD) {
            overrun = true;
            break;
        }
    }
    if (overrun) {
        wprintf(L"[!] Buffer overrun detected after CopyPixels!\n");
        return false;
    }
    wprintf(L"[+] CopyPixels completed safely. Buffer size: %u bytes\n", bufferSize);
    return true;
}

void SaveResult(bool success) {
    if (!g_resultFile.empty()) {
        std::wofstream ofs(g_resultFile, std::ios::trunc);
        if (ofs) {
            ofs << (success ? L"success" : L"failure");
        }
    }
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

    if (g_advancedDebug) {
        wprintf(L"[+] Opening image: %s\n", imagePath);
        wprintf(L"Process ID: %lu\n", GetCurrentProcessId());
        wprintf(L"Thread ID: %lu\n", GetCurrentThreadId());
        PrintLoadedModules(L"Before COM Init");
        PrintMemoryUsage(L"Before COM Init");
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    TrackSubCall("ole32", "ole32", "CoInitializeEx");
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CoInitializeEx", hr);
        success = false;
        SaveResult(success);
        return -1;
    }

    IWICImagingFactory* pFactory = nullptr;
    hr = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pFactory)
    );
    TrackSubCall("ole32", "ole32", "CoCreateInstance");
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CoCreateInstance (WICImagingFactory)", hr);
        CoUninitialize();
        success = false;
        SaveResult(success);
        return -1;
    }
    if (g_advancedDebug) {
        wprintf(L"[+] WIC Factory created\n");
        PrintLoadedModules(L"After Factory Init");
        PrintMemoryUsage(L"After Factory Init");
    }

    IWICBitmapDecoder* pDecoder = nullptr;
    hr = pFactory->CreateDecoderFromFilename(
        imagePath,
        nullptr,
        GENERIC_READ,
        WICDecodeMetadataCacheOnLoad,
        &pDecoder
    );
    TrackSubCall("wincodec", "wincodec", "CreateDecoderFromFilename");
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"CreateDecoderFromFilename", hr);
        pFactory->Release();
        CoUninitialize();
        success = false;
        SaveResult(success);
        return -1;
    }

    if (g_advancedDebug) {
        PrintLoadedModules(L"After Decoder Creation");
    }

    IWICBitmapDecoderInfo* pDecoderInfo = nullptr;
    hr = pDecoder->GetDecoderInfo(&pDecoderInfo);
    TrackSubCall("wincodec", "wincodec", "GetDecoderInfo");
    if (SUCCEEDED(hr) && pDecoderInfo) {
        WCHAR friendlyName[128] = {};
        UINT cchActual = 0;
        hr = pDecoderInfo->GetFriendlyName(128, friendlyName, &cchActual);
        TrackSubCall("wincodec", "wincodec", "GetFriendlyName");
        if (SUCCEEDED(hr)) {
            if (g_advancedDebug) wprintf(L"[+] Decoder Info: %s\n", friendlyName);
        } else {
            if (g_advancedDebug) PrintError(L"GetFriendlyName", hr);
        }
        pDecoderInfo->Release();
    }

    if (g_advancedDebug) {
        PrintMemoryUsage(L"After Decoder Init");
    }

    IWICBitmapFrameDecode* pFrame = nullptr;
    hr = pDecoder->GetFrame(0, &pFrame);
    TrackSubCall("wincodec", "wincodec", "GetFrame");
    if (FAILED(hr)) {
        if (g_advancedDebug) PrintError(L"GetFrame(0)", hr);
        pDecoder->Release();
        pFactory->Release();
        CoUninitialize();
        success = false;
        SaveResult(success);
        return -1;
    }

    if (g_advancedDebug) {
        PrintLoadedModules(L"After Frame Decode");
    }

    UINT width = 0, height = 0;
    hr = pFrame->GetSize(&width, &height);
    TrackSubCall("wincodec", "wincodec", "GetSize");
    if (SUCCEEDED(hr)) {
        if (g_advancedDebug) wprintf(L"[+] Image dimensions: %ux%u\n", width, height);
    }

    WICPixelFormatGUID format = {};
    hr = pFrame->GetPixelFormat(&format);
    TrackSubCall("wincodec", "wincodec", "GetPixelFormat");
    if (SUCCEEDED(hr)) {
        LPOLESTR guidStr = nullptr;
        hr = StringFromCLSID(format, &guidStr);
        TrackSubCall("ole32", "ole32", "StringFromCLSID");
        if (SUCCEEDED(hr)) {
            if (g_advancedDebug) wprintf(L"[+] Pixel format GUID: %s\n", guidStr);
            CoTaskMemFree(guidStr);
        } else {
            if (g_advancedDebug) PrintError(L"StringFromCLSID", hr);
        }
    }

    if (g_advancedDebug) {
        wprintf(L"Process ID: %lu\n", GetCurrentProcessId());
        wprintf(L"WICImagingFactory address: %p\n", static_cast<void*>(pFactory));
        wprintf(L"WICBitmapDecoder address: %p\n", static_cast<void*>(pDecoder));
        wprintf(L"WICBitmapFrameDecode address: %p\n", static_cast<void*>(pFrame));
        PrintMemoryUsage(L"After Frame Decode");
        PrintWICWeaknesses();
    } else {
        PrintWICBasics();
    }

    pFrame->Release();
    pDecoder->Release();
    pFactory->Release();

    CoUninitialize();
    TrackSubCall("ole32", "ole32", "CoUninitialize");

    if (g_advancedDebug) {
        PrintLoadedModules(L"After COM Uninit");
        PrintMemoryUsage(L"After COM Uninit");
        wprintf(L"[+] Finished without critical failure.\n");
    }

    SaveResult(success);
    return 0;
}
