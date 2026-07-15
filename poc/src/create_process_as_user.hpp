#ifndef CREATE_PROCESS_AS_USER_HPP
#define CREATE_PROCESS_AS_USER_HPP

#if !defined(_WIN32)
#error "create_process_as_user.hpp requires Windows."
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <UserEnv.h>
#include <WtsApi32.h>

#include <string>
#include <vector>

#if defined(_MSC_VER) && !defined(CREATE_PROCESS_AS_USER_HPP_NO_AUTOLINK)
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")
#endif

namespace session0_launcher {

namespace detail {

class scoped_handle {
public:
    scoped_handle() = default;
    explicit scoped_handle(HANDLE handle) noexcept : handle_(handle) {}

    scoped_handle(const scoped_handle&) = delete;
    scoped_handle& operator=(const scoped_handle&) = delete;

    scoped_handle(scoped_handle&& other) noexcept : handle_(other.release()) {}

    scoped_handle& operator=(scoped_handle&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~scoped_handle()
    {
        reset();
    }

    HANDLE get() const noexcept
    {
        return handle_;
    }

    HANDLE release() noexcept
    {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

    void reset(HANDLE handle = nullptr) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

class scoped_environment_block {
public:
    scoped_environment_block() = default;
    explicit scoped_environment_block(LPVOID environment) noexcept : environment_(environment) {}

    scoped_environment_block(const scoped_environment_block&) = delete;
    scoped_environment_block& operator=(const scoped_environment_block&) = delete;

    scoped_environment_block(scoped_environment_block&& other) noexcept : environment_(other.release()) {}

    scoped_environment_block& operator=(scoped_environment_block&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~scoped_environment_block()
    {
        reset();
    }

    LPVOID get() const noexcept
    {
        return environment_;
    }

    LPVOID release() noexcept
    {
        LPVOID environment = environment_;
        environment_ = nullptr;
        return environment;
    }

    void reset(LPVOID environment = nullptr) noexcept
    {
        if (environment_ != nullptr) {
            ::DestroyEnvironmentBlock(environment_);
        }
        environment_ = environment;
    }

private:
    LPVOID environment_ = nullptr;
};

class scoped_wts_memory {
public:
    scoped_wts_memory() = default;
    explicit scoped_wts_memory(PVOID memory) noexcept : memory_(memory) {}

    scoped_wts_memory(const scoped_wts_memory&) = delete;
    scoped_wts_memory& operator=(const scoped_wts_memory&) = delete;

    scoped_wts_memory(scoped_wts_memory&& other) noexcept : memory_(other.release()) {}

    scoped_wts_memory& operator=(scoped_wts_memory&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~scoped_wts_memory()
    {
        reset();
    }

    PVOID get() const noexcept
    {
        return memory_;
    }

    PVOID release() noexcept
    {
        PVOID memory = memory_;
        memory_ = nullptr;
        return memory;
    }

    void reset(PVOID memory = nullptr) noexcept
    {
        if (memory_ != nullptr) {
            ::WTSFreeMemory(memory_);
        }
        memory_ = memory;
    }

private:
    PVOID memory_ = nullptr;
};

inline std::wstring format_windows_error(DWORD error_code)
{
    LPWSTR raw_message = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = ::FormatMessageW(
        flags,
        nullptr,
        error_code,
        0,
        reinterpret_cast<LPWSTR>(&raw_message),
        0,
        nullptr);

    if (length == 0 || raw_message == nullptr) {
        return L"Unknown error";
    }

    std::wstring message(raw_message, length);
    ::LocalFree(raw_message);

    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ' || message.back() == L'\t')) {
        message.pop_back();
    }

    return message;
}

inline void fill_error(
    const wchar_t* step,
    DWORD error_code,
    std::wstring* error_message,
    DWORD* win32_error) noexcept
{
    if (win32_error != nullptr) {
        *win32_error = error_code;
    }

    if (error_message != nullptr) {
        *error_message = std::wstring(step) + L" failed. error=" + std::to_wstring(error_code) +
                         L" (" + format_windows_error(error_code) + L")";
    }
}

inline bool get_active_session_id(DWORD* session_id)
{
    if (session_id == nullptr) {
        return false;
    }

    *session_id = 0xFFFFFFFF;

    PWTS_SESSION_INFOW session_info = nullptr;
    DWORD session_count = 0;
    if (::WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &session_info, &session_count)) {
        scoped_wts_memory session_memory(session_info);
        for (DWORD index = 0; index < session_count; ++index) {
            const WTS_SESSION_INFOW& current = session_info[index];
            if (current.State == WTSActive) {
                *session_id = current.SessionId;
                return true;
            }
        }
    }

    *session_id = ::WTSGetActiveConsoleSessionId();
    return *session_id != 0xFFFFFFFF;
}

inline bool get_primary_user_token(HANDLE* token, std::wstring* error_message, DWORD* win32_error)
{
    if (token == nullptr) {
        fill_error(L"get_primary_user_token", ERROR_INVALID_PARAMETER, error_message, win32_error);
        return false;
    }

    *token = nullptr;

    DWORD session_id = 0;
    if (!get_active_session_id(&session_id)) {
        fill_error(L"GetActiveSessionId", ERROR_NO_TOKEN, error_message, win32_error);
        return false;
    }

    HANDLE impersonation_token = nullptr;
    if (!::WTSQueryUserToken(session_id, &impersonation_token)) {
        fill_error(L"WTSQueryUserToken", ::GetLastError(), error_message, win32_error);
        return false;
    }
    scoped_handle impersonation_token_guard(impersonation_token);

    HANDLE primary_token = nullptr;
    if (!::DuplicateTokenEx(
            impersonation_token_guard.get(),
            0,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primary_token)) {
        fill_error(L"DuplicateTokenEx", ::GetLastError(), error_message, win32_error);
        return false;
    }

    *token = primary_token;
    return true;
}

inline bool is_local_system_token(HANDLE token, std::wstring* error_message, DWORD* win32_error)
{
    DWORD token_info_size = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &token_info_size);
    if (token_info_size == 0 || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fill_error(L"GetTokenInformation", ::GetLastError(), error_message, win32_error);
        return false;
    }

    std::vector<BYTE> token_info(token_info_size);
    if (!::GetTokenInformation(token, TokenUser, token_info.data(), token_info_size, &token_info_size)) {
        fill_error(L"GetTokenInformation", ::GetLastError(), error_message, win32_error);
        return false;
    }

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID local_system_sid = nullptr;
    if (!::AllocateAndInitializeSid(
            &nt_authority,
            1,
            SECURITY_LOCAL_SYSTEM_RID,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &local_system_sid)) {
        fill_error(L"AllocateAndInitializeSid", ::GetLastError(), error_message, win32_error);
        return false;
    }

    const bool matches = ::EqualSid(reinterpret_cast<TOKEN_USER*>(token_info.data())->User.Sid, local_system_sid) != FALSE;
    ::FreeSid(local_system_sid);

    if (!matches) {
        if (win32_error != nullptr) {
            *win32_error = ERROR_ACCESS_DENIED;
        }
        if (error_message != nullptr) {
            *error_message = L"Current process token is not LocalSystem.";
        }
    }

    return matches;
}

inline bool get_current_process_system_token_for_session(
    DWORD session_id,
    HANDLE* token,
    std::wstring* error_message,
    DWORD* win32_error)
{
    if (token == nullptr) {
        fill_error(L"get_current_process_system_token_for_session", ERROR_INVALID_PARAMETER, error_message, win32_error);
        return false;
    }

    *token = nullptr;

    HANDLE current_process_token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &current_process_token)) {
        fill_error(L"OpenProcessToken", ::GetLastError(), error_message, win32_error);
        return false;
    }
    scoped_handle current_process_token_guard(current_process_token);

    if (!is_local_system_token(current_process_token_guard.get(), error_message, win32_error)) {
        return false;
    }

    HANDLE primary_token = nullptr;
    const DWORD desired_access =
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
    if (!::DuplicateTokenEx(
            current_process_token_guard.get(),
            desired_access,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primary_token)) {
        fill_error(L"DuplicateTokenEx", ::GetLastError(), error_message, win32_error);
        return false;
    }
    scoped_handle primary_token_guard(primary_token);

    if (!::SetTokenInformation(primary_token_guard.get(), TokenSessionId, &session_id, sizeof(session_id))) {
        fill_error(L"SetTokenInformation(TokenSessionId)", ::GetLastError(), error_message, win32_error);
        return false;
    }

    *token = primary_token_guard.release();
    return true;
}

inline std::vector<wchar_t> make_mutable_buffer(const std::wstring& value)
{
    if (value.empty()) {
        return {};
    }

    std::vector<wchar_t> buffer(value.begin(), value.end());
    buffer.push_back(L'\0');
    return buffer;
}

inline bool create_process_with_token(
    HANDLE token,
    const std::wstring& application_path,
    const std::wstring& command_line,
    const std::wstring& working_directory,
    bool visible,
    DWORD* process_id,
    std::wstring* error_message,
    DWORD* win32_error)
{
    LPVOID environment = nullptr;
    if (!::CreateEnvironmentBlock(&environment, token, FALSE)) {
        fill_error(L"CreateEnvironmentBlock", ::GetLastError(), error_message, win32_error);
        return false;
    }
    scoped_environment_block environment_guard(environment);

    STARTUPINFOW startup_info = {};
    startup_info.cb = sizeof(startup_info);
    startup_info.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startup_info.dwFlags = STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = static_cast<WORD>(visible ? SW_SHOW : SW_HIDE);

    PROCESS_INFORMATION process_info = {};
    const DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT | (visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
    std::vector<wchar_t> mutable_command_line = make_mutable_buffer(command_line);

    const LPWSTR current_directory =
        working_directory.empty() ? nullptr : const_cast<LPWSTR>(working_directory.c_str());
    const LPWSTR command_line_buffer =
        mutable_command_line.empty() ? nullptr : mutable_command_line.data();

    if (!::CreateProcessAsUserW(
            token,
            application_path.c_str(),
            command_line_buffer,
            nullptr,
            nullptr,
            FALSE,
            creation_flags,
            environment_guard.get(),
            current_directory,
            &startup_info,
            &process_info)) {
        fill_error(L"CreateProcessAsUserW", ::GetLastError(), error_message, win32_error);
        return false;
    }

    scoped_handle process_guard(process_info.hProcess);
    scoped_handle thread_guard(process_info.hThread);

    if (process_id != nullptr) {
        *process_id = process_info.dwProcessId;
    }

    return true;
}

}  // namespace detail

// Starts a process in the currently active user session from Session 0.
// The caller usually needs to run as LocalSystem and hold SeTcbPrivilege.
// `command_line` is passed directly to CreateProcessAsUserW. Some target
// applications expect argv[0] to be included, so build this string accordingly.
inline bool StartProcessAsCurrentUser(
    const std::wstring& application_path,
    const std::wstring& command_line = L"",
    const std::wstring& working_directory = L"",
    bool visible = true,
    DWORD* process_id = nullptr,
    std::wstring* error_message = nullptr,
    DWORD* win32_error = nullptr)
{
    if (process_id != nullptr) {
        *process_id = 0;
    }
    if (win32_error != nullptr) {
        *win32_error = ERROR_SUCCESS;
    }
    if (error_message != nullptr) {
        error_message->clear();
    }

    if (application_path.empty()) {
        detail::fill_error(L"StartProcessAsCurrentUser", ERROR_INVALID_PARAMETER, error_message, win32_error);
        return false;
    }

    HANDLE user_token = nullptr;
    if (!detail::get_primary_user_token(&user_token, error_message, win32_error)) {
        return false;
    }
    detail::scoped_handle user_token_guard(user_token);

    return detail::create_process_with_token(
        user_token_guard.get(),
        application_path,
        command_line,
        working_directory,
        visible,
        process_id,
        error_message,
        win32_error);
}

// Starts a process in the active user session while preserving the current
// process token. If the caller runs as LocalSystem, the child process remains
// LocalSystem and becomes visible on the interactive desktop.
inline bool StartProcessAsSystemInActiveSession(
    const std::wstring& application_path,
    const std::wstring& command_line = L"",
    const std::wstring& working_directory = L"",
    bool visible = true,
    DWORD* process_id = nullptr,
    std::wstring* error_message = nullptr,
    DWORD* win32_error = nullptr)
{
    if (process_id != nullptr) {
        *process_id = 0;
    }
    if (win32_error != nullptr) {
        *win32_error = ERROR_SUCCESS;
    }
    if (error_message != nullptr) {
        error_message->clear();
    }

    if (application_path.empty()) {
        detail::fill_error(L"StartProcessAsSystemInActiveSession", ERROR_INVALID_PARAMETER, error_message, win32_error);
        return false;
    }

    DWORD session_id = 0;
    if (!detail::get_active_session_id(&session_id)) {
        detail::fill_error(L"GetActiveSessionId", ERROR_NO_TOKEN, error_message, win32_error);
        return false;
    }

    HANDLE system_token = nullptr;
    if (!detail::get_current_process_system_token_for_session(session_id, &system_token, error_message, win32_error)) {
        return false;
    }
    detail::scoped_handle system_token_guard(system_token);

    return detail::create_process_with_token(
        system_token_guard.get(),
        application_path,
        command_line,
        working_directory,
        visible,
        process_id,
        error_message,
        win32_error);
}

}  // namespace session0_launcher

#endif  // CREATE_PROCESS_AS_USER_HPP
