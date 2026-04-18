#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static const wchar_t *EFI_GLOBAL_VARIABLE_GUID = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

#pragma pack(push, 1)
typedef struct {
    GUID  SignatureType;
    UINT32 SignatureListSize;
    UINT32 SignatureHeaderSize;
    UINT32 SignatureSize;
} EFI_SIGNATURE_LIST;
#pragma pack(pop)

static int contains_ascii_case_insensitive(const uint8_t *buf, size_t len, const char *needle) {
    size_t nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || len < nlen) return 0;

    for (size_t i = 0; i + nlen <= len; i++) {
        size_t j = 0;
        for (; j < nlen; j++) {
            unsigned char c = buf[i + j];
            unsigned char d = (unsigned char)needle[j];
            if (c >= A && c <= Z) c = (unsigned char)(c - A + a);
            if (d >= A && d <= Z) d = (unsigned char)(d - A + a);
            if (c != d) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int enable_system_environment_privilege(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return 0;

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

static int search_uefi_var_for_string(const wchar_t *varName, const char *needle) {
    DWORD attrs = 0;

    DWORD bufSize = 64 * 1024;
    uint8_t *buf = NULL;

    for (int attempt = 0; attempt < 7; attempt++) {
        buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (!buf) return -2;

        DWORD got = GetFirmwareEnvironmentVariableExW(varName, EFI_GLOBAL_VARIABLE_GUID, buf, bufSize, &attrs);
        if (got == 0) {
            DWORD err = GetLastError();
            HeapFree(GetProcessHeap(), 0, buf);
            buf = NULL;
            if (err == ERROR_INSUFFICIENT_BUFFER) { bufSize *= 2; continue; }
            if (err == ERROR_INVALID_FUNCTION) return -3;
            if (err == ERROR_PRIVILEGE_NOT_HELD) return -4;
            return -1;
        }

        size_t len = (size_t)got;

        // Fast raw scan
        if (contains_ascii_case_insensitive(buf, len, needle)) {
            HeapFree(GetProcessHeap(), 0, buf);
            return 1;
        }

        // Light parsing of EFI_SIGNATURE_LIST blocks; scan each signature blob
        size_t off = 0;
        while (off + sizeof(EFI_SIGNATURE_LIST) <= len) {
            EFI_SIGNATURE_LIST *list = (EFI_SIGNATURE_LIST*)(buf + off);
            if (list->SignatureListSize < sizeof(EFI_SIGNATURE_LIST)) break;
            if (off + list->SignatureListSize > len) break;

            size_t headerOff = off + sizeof(EFI_SIGNATURE_LIST);
            size_t sigOff = headerOff + list->SignatureHeaderSize;
            if (sigOff > off + list->SignatureListSize) break;

            size_t sigBlockLen = list->SignatureListSize - (sizeof(EFI_SIGNATURE_LIST) + list->SignatureHeaderSize);
            if (list->SignatureSize == 0) break;

            size_t count = sigBlockLen / list->SignatureSize;
            for (size_t i = 0; i < count; i++) {
                size_t oneOff = sigOff + i * list->SignatureSize;
                size_t dataOff = oneOff + sizeof(GUID);
                if (dataOff > off + list->SignatureListSize) break;
                size_t dataLen = list->SignatureSize - sizeof(GUID);
                if (dataOff + dataLen > off + list->SignatureListSize) break;

                if (contains_ascii_case_insensitive(buf + dataOff, dataLen, needle)) {
                    HeapFree(GetProcessHeap(), 0, buf);
                    return 1;
                }
            }

            off += list->SignatureListSize;
        }

        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }

    return -1;
}

int wmain(void) {
    const char *needle = "Microsoft UEFI CA 2023";

    printf("SecureBootCA2023Check\n");

    if (!enable_system_environment_privilege()) {
        printf("ERROR: Need admin (SeSystemEnvironmentPrivilege).\n");
        return 3;
    }

    // Best-effort Secure Boot state
    uint8_t sb = 0;
    DWORD attrs = 0;
    DWORD got = GetFirmwareEnvironmentVariableExW(L"SecureBoot", EFI_GLOBAL_VARIABLE_GUID, &sb, sizeof(sb), &attrs);
    if (got != 0) {
        printf("SecureBoot: %s\n", sb ? "Enabled" : "Disabled");
        if (!sb) {
            printf("Microsoft UEFI CA 2023: UNKNOWN (Secure Boot off)\n");
            return 2;
        }
    } else {
        printf("WARN: Could not read SecureBoot variable (continuing). Error=%lu\n", GetLastError());
    }

    int hit_db  = search_uefi_var_for_string(L"db",  needle);
    int hit_kek = search_uefi_var_for_string(L"KEK", needle);

    if (hit_db < 0 && hit_kek < 0) {
        printf("ERROR: Failed to read UEFI variables db/KEK (db=%d, KEK=%d).\n", hit_db, hit_kek);
        return 3;
    }

    int present = (hit_db == 1) || (hit_kek == 1);
    printf("Microsoft UEFI CA 2023: %s\n", present ? "PRESENT" : "NOT PRESENT");

    return present ? 0 : 1;
}
