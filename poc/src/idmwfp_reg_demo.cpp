#define NOMINMAX
#include <windows.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kDevicePath[] = L"\\\\.\\IDMWFP";
constexpr DWORD IOCTL_IDMWFP_SUBCOMMAND = 0x12C028;

constexpr std::uint8_t SUBCMD_QUERY      = 0x0C;
constexpr std::uint8_t SUBCMD_SET        = 0x0D;
constexpr std::uint8_t SUBCMD_DEL_VALUE  = 0x0E;
constexpr std::uint8_t SUBCMD_DEL_KEY    = 0x0F;

constexpr std::uint32_t ROOT_MACHINE = 0x1;
constexpr std::uint32_t ROOT_USER    = 0x2;

constexpr std::uint32_t REG_TYPE_SZ     = 1;
constexpr std::uint32_t REG_TYPE_EXPAND_SZ = 2;
constexpr std::uint32_t REG_TYPE_BINARY = 3;
constexpr std::uint32_t REG_TYPE_DWORD  = 4;
constexpr std::uint32_t REG_TYPE_MULTI_SZ = 7;
constexpr std::uint32_t REG_TYPE_QWORD  = 11;

struct ScopedHandle {
    HANDLE value{INVALID_HANDLE_VALUE};

    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : value(handle) {}

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ~ScopedHandle() {
        if (value != INVALID_HANDLE_VALUE && value != nullptr) {
            CloseHandle(value);
        }
    }

    [[nodiscard]] bool valid() const {
        return value != INVALID_HANDLE_VALUE && value != nullptr;
    }
};

struct IoctlResult {
    bool ok{false};
    DWORD last_error{ERROR_SUCCESS};
    DWORD bytes_returned{0};
};

[[nodiscard]] std::uint64_t parse_u64(std::string_view text) {
    std::size_t consumed = 0;
    const std::string copy(text);
    const std::uint64_t value = std::stoull(copy, &consumed, 0);
    if (consumed != copy.size()) {
        throw std::runtime_error("invalid numeric value: " + copy);
    }
    return value;
}

[[nodiscard]] std::uint32_t parse_root_flag(std::string_view text) {
    if (text == "machine" || text == "HKLM" || text == "hklm") {
        return ROOT_MACHINE;
    }
    if (text == "user" || text == "HKU" || text == "hku") {
        return ROOT_USER;
    }
    throw std::runtime_error("root must be machine|user|HKLM|HKU");
}

[[nodiscard]] std::wstring format_win32_error(DWORD code) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message;
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, buffer + length);
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
    } else {
        message = L"(no message)";
    }
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    return message;
}

[[nodiscard]] std::uint16_t rol16(std::uint16_t value, unsigned count) {
    count &= 15;
    return static_cast<std::uint16_t>(((value << count) | (value >> (16 - count))) & 0xFFFFu);
}

[[nodiscard]] std::uint8_t ror8(std::uint8_t value, unsigned count) {
    count &= 7;
    return static_cast<std::uint8_t>(((value >> count) | (value << (8 - count))) & 0xFFu);
}

[[nodiscard]] std::vector<std::uint8_t> encode_value_transport(const std::vector<std::uint8_t>& plain) {
    std::vector<std::uint8_t> out(plain.size());
    unsigned rot = 4;
    for (std::size_t i = 0; i < plain.size(); ++i) {
        const std::uint8_t b = plain[i];
        const std::uint8_t rol = static_cast<std::uint8_t>(((b << (rot & 7)) | (b >> (8 - (rot & 7)))) & 0xFFu);
        out[i] = static_cast<std::uint8_t>(((rol - 83u) & 0xFFu) ^ 0xADu);
        ++rot;
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> decode_value_transport(const std::uint8_t* encoded, std::size_t size) {
    std::vector<std::uint8_t> out(size);
    unsigned rot = 4;
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = ror8(static_cast<std::uint8_t>(((encoded[i] ^ 0xADu) + 83u) & 0xFFu), rot);
        ++rot;
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_reg_path_utf16(std::string_view ascii_path) {
    std::vector<std::uint8_t> encoded;
    encoded.reserve(ascii_path.size() * 2);
    unsigned rot = 4;
    for (unsigned char ch : ascii_path) {
        const std::uint16_t wide = static_cast<std::uint16_t>(ch);
        const std::uint16_t enc = static_cast<std::uint16_t>(((rol16(wide, rot) - 9555u) & 0xFFFFu) ^ 0xDAADu);
        encoded.push_back(static_cast<std::uint8_t>(enc & 0xFFu));
        encoded.push_back(static_cast<std::uint8_t>(enc >> 8));
        ++rot;
    }
    return encoded;
}

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open file: " + path);
    }
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size < 0) {
        throw std::runtime_error("failed to determine file size: " + path);
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(bytes.data()), size);
        if (!file) {
            throw std::runtime_error("failed to read file: " + path);
        }
    }
    return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> parse_hex_bytes(std::string_view text) {
    std::string filtered;
    filtered.reserve(text.size());
    for (unsigned char ch : text) {
        if (std::isxdigit(ch)) {
            filtered.push_back(static_cast<char>(ch));
        }
    }
    if (filtered.size() % 2 != 0) {
        throw std::runtime_error("hex string must contain an even number of hex digits");
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(filtered.size() / 2);
    for (std::size_t i = 0; i < filtered.size(); i += 2) {
        const std::string piece = filtered.substr(i, 2);
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(piece, nullptr, 16)));
    }
    return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> encode_utf16le_text(const std::string& text) {
    const int wchar_count = MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, nullptr, 0);
    if (wchar_count <= 0) {
        throw std::runtime_error("MultiByteToWideChar failed");
    }
    std::vector<wchar_t> wide(static_cast<std::size_t>(wchar_count));
    if (MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, wide.data(), wchar_count) <= 0) {
        throw std::runtime_error("MultiByteToWideChar failed");
    }
    const std::size_t byte_count = static_cast<std::size_t>(wchar_count) * sizeof(wchar_t);
    std::vector<std::uint8_t> bytes(byte_count);
    std::memcpy(bytes.data(), wide.data(), byte_count);
    return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> encode_utf16le_multi_sz(std::string_view text) {
    std::vector<std::uint8_t> bytes;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t sep = text.find('|', start);
        const std::size_t end = (sep == std::string_view::npos) ? text.size() : sep;
        const std::string part(text.substr(start, end - start));
        std::vector<std::uint8_t> wide = encode_utf16le_text(part);
        bytes.insert(bytes.end(), wide.begin(), wide.end());
        if (sep == std::string_view::npos) {
            break;
        }
        start = sep + 1;
    }
    const std::uint16_t terminator = 0;
    bytes.push_back(static_cast<std::uint8_t>(terminator & 0xFFu));
    bytes.push_back(static_cast<std::uint8_t>(terminator >> 8));
    return bytes;
}

void dump_hex(const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    for (std::size_t offset = 0; offset < size; offset += 16) {
        std::printf("%04zx  ", offset);
        for (std::size_t i = 0; i < 16; ++i) {
            if (offset + i < size) {
                std::printf("%02X ", bytes[offset + i]);
            } else {
                std::printf("   ");
            }
        }
        std::printf(" ");
        for (std::size_t i = 0; i < 16 && offset + i < size; ++i) {
            const unsigned char c = bytes[offset + i];
            std::printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        std::printf("\n");
    }
}

[[nodiscard]] ScopedHandle open_driver() {
    HANDLE raw = CreateFileW(
        kDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (raw == INVALID_HANDLE_VALUE || raw == nullptr) {
        const DWORD error = GetLastError();
        throw std::runtime_error("CreateFileW failed, win32=" + std::to_string(error));
    }
    return ScopedHandle(raw);
}

IoctlResult send_ioctl(
    HANDLE device,
    DWORD code,
    void* in_buffer,
    DWORD in_size,
    void* out_buffer,
    DWORD out_size)
{
    DWORD bytes_returned = 0;
    const BOOL ok = DeviceIoControl(
        device,
        code,
        in_buffer,
        in_size,
        out_buffer,
        out_size,
        &bytes_returned,
        nullptr);

    IoctlResult result;
    result.ok = (ok != FALSE);
    result.last_error = result.ok ? ERROR_SUCCESS : GetLastError();
    result.bytes_returned = bytes_returned;
    return result;
}

void print_ioctl_result(const char* name, const IoctlResult& result) {
    std::printf("%s: %s", name, result.ok ? "OK" : "FAIL");
    if (!result.ok) {
        const std::wstring msg = format_win32_error(result.last_error);
        std::printf(" - win32=%lu (0x%08lX)", static_cast<unsigned long>(result.last_error), static_cast<unsigned long>(result.last_error));
        if (!msg.empty()) {
            std::printf(" %ls", msg.c_str());
        }
    }
    std::printf(", bytes_returned=%lu\n", static_cast<unsigned long>(result.bytes_returned));
}

[[nodiscard]] std::vector<std::uint8_t> build_reg_packet(
    std::uint8_t subcmd,
    std::uint32_t flags,
    std::string_view relative_path_with_value,
    const std::vector<std::uint8_t>& data,
    std::uint16_t value_type)
{
    const std::vector<std::uint8_t> enc_path = encode_reg_path_utf16(relative_path_with_value);
    const std::uint16_t path_off = 20;
    const std::uint16_t path_wchars = static_cast<std::uint16_t>(relative_path_with_value.size());
    const std::uint16_t data_off = static_cast<std::uint16_t>(path_off + enc_path.size());
    const std::uint16_t data_size = static_cast<std::uint16_t>(data.size());

    std::vector<std::uint8_t> packet(path_off + enc_path.size() + data.size(), 0);
    packet[0] = subcmd;
    packet[1] = 0;
    std::memcpy(packet.data() + 4, &flags, sizeof(flags));
    std::memcpy(packet.data() + 8, &path_off, sizeof(path_off));
    std::memcpy(packet.data() + 10, &path_wchars, sizeof(path_wchars));
    std::memcpy(packet.data() + 12, &data_off, sizeof(data_off));
    std::memcpy(packet.data() + 14, &data_size, sizeof(data_size));
    std::memcpy(packet.data() + 16, &value_type, sizeof(value_type));
    packet[18] = 0;
    packet[19] = 0;
    std::memcpy(packet.data() + path_off, enc_path.data(), enc_path.size());
    if (!data.empty()) {
        std::memcpy(packet.data() + data_off, data.data(), data.size());
    }
    return packet;
}

[[nodiscard]] std::uint32_t parse_optional_flags(const std::vector<std::string>& args, std::size_t index, std::uint32_t root_flag) {
    if (args.size() > index) {
        return root_flag | static_cast<std::uint32_t>(parse_u64(args[index]));
    }
    return root_flag;
}

int cmd_reg_query(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::fprintf(stderr, "usage: query <machine|user> <relative_path\\\\ValueName> [out_size] [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::size_t out_size = (args.size() >= 4) ? static_cast<std::size_t>(parse_u64(args[3])) : 64;
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_QUERY, flags, args[2], {}, 0);
    std::vector<std::uint8_t> output(out_size, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("query", result);
    if (result.bytes_returned > 0 && result.bytes_returned <= output.size()) {
        dump_hex(output.data(), result.bytes_returned);
        if (result.bytes_returned >= 12) {
            const std::uint32_t title_index = *reinterpret_cast<const std::uint32_t*>(output.data() + 0);
            const std::uint32_t type = *reinterpret_cast<const std::uint32_t*>(output.data() + 4);
            const std::uint32_t data_len = *reinterpret_cast<const std::uint32_t*>(output.data() + 8);
            std::printf("decoded: title_index=%u type=%u data_len=%u\n", title_index, type, data_len);
            if (result.bytes_returned >= 12 + data_len) {
                const std::uint8_t* encoded = output.data() + 12;
                const std::vector<std::uint8_t> plain = decode_value_transport(encoded, data_len);
                std::puts("decoded data:");
                dump_hex(plain.data(), plain.size());
                const std::uint8_t* data = plain.data();
                if (type == REG_TYPE_DWORD && data_len >= 4) {
                    std::printf("value(dword)=0x%08X\n", *reinterpret_cast<const std::uint32_t*>(data));
                } else if (type == REG_TYPE_QWORD && data_len >= 8) {
                    std::printf("value(qword)=0x%016llX\n", static_cast<unsigned long long>(*reinterpret_cast<const std::uint64_t*>(data)));
                } else if ((type == REG_TYPE_SZ || type == REG_TYPE_EXPAND_SZ) && data_len >= 2) {
                    const wchar_t* ws = reinterpret_cast<const wchar_t*>(data);
                    const std::size_t wchar_count = data_len / sizeof(wchar_t);
                    std::wstring w(ws, ws + wchar_count);
                    while (!w.empty() && w.back() == L'\0') {
                        w.pop_back();
                    }
                    if (type == REG_TYPE_EXPAND_SZ) {
                        std::wcout << L"value(expand_sz)=" << w << L"\n";
                    } else {
                        std::wcout << L"value(string)=" << w << L"\n";
                    }
                } else if (type == REG_TYPE_MULTI_SZ && data_len >= 2) {
                    const wchar_t* ws = reinterpret_cast<const wchar_t*>(data);
                    const std::size_t wchar_count = data_len / sizeof(wchar_t);
                    std::wcout << L"value(multi_sz):\n";
                    std::size_t i = 0;
                    std::size_t index = 0;
                    while (i < wchar_count) {
                        std::size_t j = i;
                        while (j < wchar_count && ws[j] != L'\0') {
                            ++j;
                        }
                        if (j == i) {
                            break;
                        }
                        std::wstring item(ws + i, ws + j);
                        std::wcout << L"  [" << index++ << L"] " << item << L"\n";
                        i = j + 1;
                    }
                } else if (type == REG_TYPE_BINARY) {
                    std::puts("value(binary) shown above");
                }
            }
        }
    }
    return result.ok ? 0 : 2;
}

int cmd_reg_set_dword(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-dword <machine|user> <relative_path\\\\ValueName> <u32> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    const std::uint32_t value = static_cast<std::uint32_t>(parse_u64(args[3]));
    std::vector<std::uint8_t> data(sizeof(value));
    std::memcpy(data.data(), &value, sizeof(value));
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_DWORD);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-dword", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_qword(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-qword <machine|user> <relative_path\\\\ValueName> <u64> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    const std::uint64_t value = parse_u64(args[3]);
    std::vector<std::uint8_t> data(sizeof(value));
    std::memcpy(data.data(), &value, sizeof(value));
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_QWORD);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-qword", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_string(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-string <machine|user> <relative_path\\\\ValueName> <text> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    std::vector<std::uint8_t> data = encode_utf16le_text(args[3]);
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_SZ);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-string", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_expand_string(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-expand-string <machine|user> <relative_path\\\\ValueName> <text> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    std::vector<std::uint8_t> data = encode_utf16le_text(args[3]);
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_EXPAND_SZ);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-expand-string", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_multi_string(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-multi-string <machine|user> <relative_path\\\\ValueName> <item1|item2|item3> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    std::vector<std::uint8_t> data = encode_utf16le_multi_sz(args[3]);
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_MULTI_SZ);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-multi-string", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_binary(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 4) {
        std::fprintf(stderr, "usage: set-binary <machine|user> <relative_path\\\\ValueName> <hex_bytes> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 5) ? parse_optional_flags(args, 4, root_flag) : root_flag;
    std::vector<std::uint8_t> data = parse_hex_bytes(args[3]);
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), REG_TYPE_BINARY);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-binary", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_set_file(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 5) {
        std::fprintf(stderr, "usage: set-file <machine|user> <relative_path\\\\ValueName> <type_num> <file> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 6) ? parse_optional_flags(args, 5, root_flag) : root_flag;
    const std::uint16_t type = static_cast<std::uint16_t>(parse_u64(args[3]));
    std::vector<std::uint8_t> data = read_file_bytes(args[4]);
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_SET, flags, args[2], encode_value_transport(data), type);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("set-file", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_del_value(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::fprintf(stderr, "usage: del-value <machine|user> <relative_path\\\\ValueName> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 4) ? parse_optional_flags(args, 3, root_flag) : root_flag;
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_DEL_VALUE, flags, args[2], {}, 0);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("del-value", result);
    return result.ok ? 0 : 2;
}

int cmd_reg_del_key(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::fprintf(stderr, "usage: del-key <machine|user> <relative_path\\\\ValueName> [extra_flags]\n");
        return 1;
    }
    const std::uint32_t root_flag = parse_root_flag(args[1]);
    const std::uint32_t flags = (args.size() >= 4) ? parse_optional_flags(args, 3, root_flag) : root_flag;
    std::vector<std::uint8_t> packet = build_reg_packet(SUBCMD_DEL_KEY, flags, args[2], {}, 0);
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("del-key", result);
    return result.ok ? 0 : 2;
}

int cmd_volume_query(HANDLE device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::fprintf(stderr, "usage: volume-query <drive_letter|0>\n");
        return 1;
    }
    std::vector<std::uint8_t> packet(24, 0);
    packet[0] = 0x10;
    if (args[1] != "0") {
        packet[8] = static_cast<std::uint8_t>(args[1][0]);
    }
    std::vector<std::uint8_t> output(16, 0);
    IoctlResult result = send_ioctl(device, IOCTL_IDMWFP_SUBCOMMAND, packet.data(), static_cast<DWORD>(packet.size()), output.data(), static_cast<DWORD>(output.size()));
    print_ioctl_result("volume-query", result);
    if (result.ok) {
        dump_hex(output.data(), output.size());
        std::vector<std::uint8_t> dec(output.size());
        unsigned rot = 4;
        for (std::size_t i = 0; i < output.size(); ++i) {
            dec[i] = ror8(static_cast<std::uint8_t>(((output[i] ^ 0xADu) + 83u) & 0xFFu), rot);
            ++rot;
        }
        std::puts("decoded:");
        dump_hex(dec.data(), dec.size());
        const std::uint64_t creation_time = *reinterpret_cast<const std::uint64_t*>(dec.data() + 0);
        const std::uint32_t volume_serial = *reinterpret_cast<const std::uint32_t*>(dec.data() + 8);
        const char drive = static_cast<char>(dec[12]);
        std::printf("decoded: creation_time=0x%llX volume_serial=0x%08X drive=%c\n",
            static_cast<unsigned long long>(creation_time),
            volume_serial,
            drive ? drive : '?');
    }
    return result.ok ? 0 : 2;
}

void print_usage() {
    std::puts("idmwfp_reg_demo - registry-focused demo for subcmd 0x0C..0x0F");
    std::puts("");
    std::puts("usage:");
    std::puts("  idmwfp_reg_demo query <machine|user> <relative_path\\ValueName> [out_size] [extra_flags]");
    std::puts("  idmwfp_reg_demo set-dword <machine|user> <relative_path\\ValueName> <u32> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-qword <machine|user> <relative_path\\ValueName> <u64> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-string <machine|user> <relative_path\\ValueName> <text> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-expand-string <machine|user> <relative_path\\ValueName> <text> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-multi-string <machine|user> <relative_path\\ValueName> <item1|item2|item3> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-binary <machine|user> <relative_path\\ValueName> <hex_bytes> [extra_flags]");
    std::puts("  idmwfp_reg_demo set-file <machine|user> <relative_path\\ValueName> <type_num> <file> [extra_flags]");
    std::puts("  idmwfp_reg_demo del-value <machine|user> <relative_path\\ValueName> [extra_flags]");
    std::puts("  idmwfp_reg_demo del-key <machine|user> <relative_path\\ValueName> [extra_flags]");
    std::puts("  idmwfp_reg_demo volume-query <drive_letter|0>");
    std::puts("");
    std::puts("notes:");
    std::puts("  - root 'machine' maps to \\\\REGISTRY\\\\MACHINE\\\\");
    std::puts("  - root 'user' maps to \\\\REGISTRY\\\\USER\\\\");
    std::puts("  - path format is relative_key_path\\\\ValueName");
    std::puts("  - use ValueName '@' for default value if needed");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 1;
        }

        const std::vector<std::string> args(argv, argv + argc);
        const std::string& command = args[1];
        ScopedHandle device = open_driver();

        if (command == "query") {
            return cmd_reg_query(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-dword") {
            return cmd_reg_set_dword(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-qword") {
            return cmd_reg_set_qword(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-string") {
            return cmd_reg_set_string(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-expand-string") {
            return cmd_reg_set_expand_string(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-multi-string") {
            return cmd_reg_set_multi_string(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-binary") {
            return cmd_reg_set_binary(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "set-file") {
            return cmd_reg_set_file(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "del-value") {
            return cmd_reg_del_value(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "del-key") {
            return cmd_reg_del_key(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }
        if (command == "volume-query") {
            return cmd_volume_query(device.value, std::vector<std::string>(args.begin() + 1, args.end()));
        }

        print_usage();
        return 1;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "error: %s\n", ex.what());
        return 2;
    }
}
