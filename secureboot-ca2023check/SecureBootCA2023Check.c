#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "comctl32.lib")

static const wchar_t *EFI_GLOBAL_VARIABLE_GUID = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
static const wchar_t *APP_TITLE = L"2nd Shop Secureboot Checker";

// Window handles
static HWND g_hMainWnd = NULL;
static HWND g_hListView = NULL;
static HWND g_hStatusLabel = NULL;
static HWND g_hBtnReadVars = NULL;
static HWND g_hBtnCheckWindows = NULL;

#define ID_BTN_READVARS 1001
#define ID_BTN_CHECKWIN 1002

#pragma pack(push, 1)
typedef struct {
    GUID  SignatureType;
    UINT32 SignatureListSize;
    UINT32 SignatureHeaderSize;
    UINT32 SignatureSize;
} EFI_SIGNATURE_LIST;
#pragma pack(pop)

typedef struct {
    wchar_t varName[32];
    DWORD size;
    FILETIME lastWrite;
    int signatureCount;
    int hasCA2023;
} UEFIVarInfo;

static int enable_system_environment_privilege(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
        return 0;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &luid)) {
        CloseHandle(hToken);
        return 0;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return err == ERROR_SUCCESS;
}

static int contains_ascii_case_insensitive(const uint8_t *buf, size_t len, const char *needle) {
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || len < nlen) return 0;

    for (size_t i = 0; i + nlen <= len; i++) {
        size_t j = 0;
        for (; j < nlen; j++) {
            unsigned char c = buf[i + j];
            unsigned char d = (unsigned char)needle[j];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            if (d >= 'A' && d <= 'Z') d = (unsigned char)(d - 'A' + 'a');
            if (c != d) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int read_uefi_variable(const wchar_t *varName, uint8_t **outBuf, DWORD *outSize, FILETIME *outLastWrite) {
    DWORD attrs = 0;
    DWORD bufSize = 128 * 1024;
    uint8_t *buf = NULL;

    for (int attempt = 0; attempt < 7; attempt++) {
        buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (!buf) return -2;

        DWORD got = GetFirmwareEnvironmentVariableExW(varName, EFI_GLOBAL_VARIABLE_GUID, buf, bufSize, &attrs);
        if (got == 0) {
            DWORD err = GetLastError();
            HeapFree(GetProcessHeap(), 0, buf);
            buf = NULL;
            if (err == ERROR_INSUFFICIENT_BUFFER) { 
                bufSize *= 2; 
                continue; 
            }
            return -1;
        }

        *outBuf = buf;
        *outSize = got;
        
        // LastWrite is not directly available via GetFirmwareEnvironmentVariableExW
        // We'll set it to current time as placeholder
        GetSystemTimeAsFileTime(outLastWrite);
        return 1;
    }
    return -1;
}

static int analyze_uefi_var(const wchar_t *varName, UEFIVarInfo *info) {
    uint8_t *buf = NULL;
    DWORD size = 0;
    FILETIME lastWrite;

    int res = read_uefi_variable(varName, &buf, &size, &lastWrite);
    if (res < 0) {
        wcscpy_s(info->varName, 32, varName);
        info->size = 0;
        info->signatureCount = 0;
        info->hasCA2023 = 0;
        memset(&info->lastWrite, 0, sizeof(FILETIME));
        return res;
    }

    wcscpy_s(info->varName, 32, varName);
    info->size = size;
    info->lastWrite = lastWrite;
    info->signatureCount = 0;
    info->hasCA2023 = 0;

    // Check for CA 2023 strings
    const char *needles[] = {"Microsoft UEFI CA 2023", "Windows UEFI CA 2023"};
    for (int n = 0; n < 2; n++) {
        if (contains_ascii_case_insensitive(buf, size, needles[n])) {
            info->hasCA2023 = 1;
            break;
        }
    }

    // Count signature lists
    size_t off = 0;
    while (off + sizeof(EFI_SIGNATURE_LIST) <= size) {
        EFI_SIGNATURE_LIST *list = (EFI_SIGNATURE_LIST*)(buf + off);
        if (list->SignatureListSize < sizeof(EFI_SIGNATURE_LIST)) break;
        if (off + list->SignatureListSize > size) break;

        size_t sigOff = off + sizeof(EFI_SIGNATURE_LIST) + list->SignatureHeaderSize;
        if (list->SignatureSize > 0) {
            size_t sigBlockLen = list->SignatureListSize - (sizeof(EFI_SIGNATURE_LIST) + list->SignatureHeaderSize);
            size_t count = sigBlockLen / list->SignatureSize;
            info->signatureCount += (int)count;
        }

        off += list->SignatureListSize;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return 1;
}

static void update_status_label(const wchar_t *text) {
    SetWindowTextW(g_hStatusLabel, text);
}

static void clear_listview(void) {
    ListView_DeleteAllItems(g_hListView);
}

static void add_listview_item(const UEFIVarInfo *info) {
    LVITEMW lvi = {0};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = ListView_GetItemCount(g_hListView);
    
    // Column 0: Variable name
    lvi.iSubItem = 0;
    lvi.pszText = (LPWSTR)info->varName;
    int idx = ListView_InsertItem(g_hListView, &lvi);

    // Column 1: Size
    wchar_t szSize[32];
    swprintf_s(szSize, 32, L"%lu Bytes", info->size);
    ListView_SetItemText(g_hListView, idx, 1, szSize);

    // Column 2: Signature count
    wchar_t szCount[32];
    swprintf_s(szCount, 32, L"%d", info->signatureCount);
    ListView_SetItemText(g_hListView, idx, 2, szCount);

    // Column 3: CA 2023 present
    ListView_SetItemText(g_hListView, idx, 3, info->hasCA2023 ? L"Ja" : L"Nein");

    // Column 4: Last Write (simplified - we don't have actual timestamp from UEFI)
    SYSTEMTIME st;
    FileTimeToSystemTime(&info->lastWrite, &st);
    wchar_t szTime[64];
    swprintf_s(szTime, 64, L"%04d-%02d-%02d %02d:%02d", 
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    ListView_SetItemText(g_hListView, idx, 4, szTime);
}

static void on_button_read_vars(void) {
    update_status_label(L"UEFI Variablen werden ausgelesen...");
    clear_listview();

    const wchar_t *varNames[] = {L"PK", L"KEK", L"db", L"dbx"};
    
    for (int i = 0; i < 4; i++) {
        UEFIVarInfo info = {0};
        analyze_uefi_var(varNames[i], &info);
        add_listview_item(&info);
    }

    update_status_label(L"UEFI Variablen ausgelesen.");
}

static void on_button_check_windows(void) {
    update_status_label(L"Prüfe Windows Zertifikatsnutzung...");
    
    // Check Secure Boot status
    uint8_t sb = 0;
    DWORD attrs = 0;
    DWORD got = GetFirmwareEnvironmentVariableExW(L"SecureBoot", EFI_GLOBAL_VARIABLE_GUID, &sb, sizeof(sb), &attrs);
    
    int secureBootActive = (got != 0 && sb != 0);
    
    // Check for CA 2023 in db/KEK
    UEFIVarInfo dbInfo = {0}, kekInfo = {0};
    analyze_uefi_var(L"db", &dbInfo);
    analyze_uefi_var(L"KEK", &kekInfo);
    
    int hasCA2023 = dbInfo.hasCA2023 || kekInfo.hasCA2023;

    wchar_t result[512] = L"";
    
    if (secureBootActive && hasCA2023) {
        wcscpy_s(result, 512, L"✓ JA, sehr wahrscheinlich\n\n"
                              L"• Secure Boot: AKTIV\n"
                              L"• UEFI CA 2023: VORHANDEN\n\n"
                              L"Windows nutzt wahrscheinlich das neuere Zertifikat.");
    } else if (!secureBootActive) {
        wcscpy_s(result, 512, L"✗ NEIN / UNKLAR\n\n"
                              L"• Secure Boot: NICHT AKTIV\n\n"
                              L"Ohne aktives Secure Boot kann keine Aussage getroffen werden.");
    } else {
        wcscpy_s(result, 512, L"✗ NEIN\n\n"
                              L"• Secure Boot: AKTIV\n"
                              L"• UEFI CA 2023: NICHT VORHANDEN\n\n"
                              L"Das neuere Zertifikat wurde nicht gefunden.");
    }

    MessageBoxW(g_hMainWnd, result, L"Windows Zertifikatsnutzung", MB_OK | MB_ICONINFORMATION);
    update_status_label(L"Prüfung abgeschlossen.");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Status label
            g_hStatusLabel = CreateWindowExW(0, L"STATIC", L"Bereit.",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                10, 10, 580, 20,
                hwnd, NULL, GetModuleHandle(NULL), NULL);

            // ListView
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                10, 40, 580, 300,
                hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            
            lvc.pszText = L"Variable";
            lvc.cx = 80;
            ListView_InsertColumn(g_hListView, 0, &lvc);
            
            lvc.pszText = L"Größe";
            lvc.cx = 100;
            ListView_InsertColumn(g_hListView, 1, &lvc);
            
            lvc.pszText = L"Einträge";
            lvc.cx = 80;
            ListView_InsertColumn(g_hListView, 2, &lvc);
            
            lvc.pszText = L"CA 2023";
            lvc.cx = 80;
            ListView_InsertColumn(g_hListView, 3, &lvc);
            
            lvc.pszText = L"Zeitstempel (ca.)";
            lvc.cx = 230;
            ListView_InsertColumn(g_hListView, 4, &lvc);

            // Buttons
            g_hBtnReadVars = CreateWindowExW(0, L"BUTTON", L"UEFI Variablen auslesen",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 350, 280, 30,
                hwnd, (HMENU)ID_BTN_READVARS, GetModuleHandle(NULL), NULL);

            g_hBtnCheckWindows = CreateWindowExW(0, L"BUTTON", L"Prüfen: Windows nutzt neuere CA?",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                310, 350, 280, 30,
                hwnd, (HMENU)ID_BTN_CHECKWIN, GetModuleHandle(NULL), NULL);

            break;
        }
        
        case WM_COMMAND: {
            if (LOWORD(wParam) == ID_BTN_READVARS) {
                on_button_read_vars();
            } else if (LOWORD(wParam) == ID_BTN_CHECKWIN) {
                on_button_check_windows();
            }
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)pCmdLine;

    if (!enable_system_environment_privilege()) {
        MessageBoxW(NULL, 
            L"Fehler: SeSystemEnvironmentPrivilege konnte nicht aktiviert werden.\n\n"
            L"Bitte als Administrator ausführen.",
            APP_TITLE, MB_OK | MB_ICONERROR);
        return 3;
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icc = {0};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    // Register window class
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"SecureBootCheckerClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassExW(&wc);

    // Create main window
    g_hMainWnd = CreateWindowExW(
        0,
        L"SecureBootCheckerClass",
        APP_TITLE,
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        620, 450,
        NULL, NULL, hInstance, NULL
    );

    if (!g_hMainWnd) {
        return 1;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    // Message loop
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
