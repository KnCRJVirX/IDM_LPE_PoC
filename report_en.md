# Internet Download Manager `idmwfp.sys` Local Privilege Escalation via Arbitrary Registry Read/Write

## 1. Summary

`idmwfp.sys` exposes a device interface accessible to all authenticated users at `\\.\IDMWFP`.

Through `IOCTL 0x12C028` and its subcommands `0x0C..0x0F`, a low-privileged local user can, **without any authorization checks**, perform the following operations on registry values under **arbitrary paths** in both `HKLM` and `HKU`:

- Read values
- Create or modify values
- Delete values
- Delete empty keys

This is not a narrowly scoped configuration interface limited to IDM-owned registry namespaces. Instead, it is a kernel-mediated registry operation primitive exposed to any authenticated user.

Because this primitive can modify:

- `HKLM\\SYSTEM\\CurrentControlSet\\Services\\...`
- Other registry paths trusted by privileged services, scheduled tasks, or system components

the issue can be used for:

- Local Privilege Escalation (LPE)
- Execution of attacker-controlled code or configuration as `SYSTEM` or in kernel-trusted contexts
- High-privilege persistence
- Tampering with security product or system configuration

From a security-impact perspective, this should be treated as a **high-severity kernel driver logic vulnerability**. At its core, it exposes an arbitrary trusted-registry read/write capability to low-privileged users.

---

## 2. Vendor and Affected Component

- Vendor: Tonec / Internet Download Manager
- Affected component: `idmwfp.sys`
- Component type: Windows kernel driver
- Device interface: `\\.\IDMWFP`

Analyzed sample:

- MD5: `7d55ad6b428320f191ed8529701ac2fa`
- SHA-256: `753a1386e7b37ee313db908183afe7238f1a2aec5e6c1e59e9c11d471b6aaa8d`

---

## 3. Vulnerability Type and Severity

### 3.1 Vulnerability Type

- Local Privilege Escalation
- Arbitrary trusted registry read/write/delete
- Missing authorization in a kernel driver / unsafe device access control

### 3.2 Root Cause Classification

Suggested CWE mappings:

- `CWE-862` Missing Authorization
- `CWE-732` Incorrect Permission Assignment for Critical Resource

### 3.3 Suggested CVSS v3.1

Suggested initial score:

- `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- Base score: `7.8`

Rationale:

- Local attack vector
- Requires only a normal authenticated low-privileged user
- No user interaction required
- Allows reading and modifying high-value system registry paths
- Can cause high-impact integrity violations and persistence

If the vendor or evaluator accepts the exploitation chain in which service or driver configuration tampering yields reliable `SYSTEM` or kernel-trusted execution, the practical LPE nature of the issue should be emphasized further.

---

## 4. Preconditions

An attacker only needs:

- Local authenticated user privileges
- The ability to open `\\.\IDMWFP`

No requirement exists for:

- Administrative privileges
- `SeRestorePrivilege` or `SeLoadDriverPrivilege`
- Debug privileges
- Interactive user confirmation

---

## 5. Root Cause

### 5.1 The Device Object Is Open to All Authenticated Users

In `DriverEntry`, the driver creates:

- `\Device\IDMWFP`
- `\DosDevices\IDMWFP`

and applies the following security descriptor:

- `D:P(A;;GA;;;AU)`

Its effect is:

- All authenticated users (`AU`) receive `GENERIC_ALL`

This means any ordinary local user can send `DeviceIoControl` requests to the device.

### 5.2 No Authorization Boundary Is Enforced on Target Registry Paths

The main `IRP_MJ_DEVICE_CONTROL` dispatcher is:

- `sub_14000E9E0`

Within it:

- `IOCTL 0x12C028`
  - Uses the first byte as a subcommand selector
  - Routes `0x0C..0x0F` to `sub_140005B90`

`sub_140005B90` performs the following:

1. Decodes a user-controlled “registry-relative path + value name”
2. Chooses a registry root prefix based on low bits in `flags`:
   - `flags & 0x1` -> `\\REGISTRY\\MACHINE\\`
   - `flags & 0x2` -> `\\REGISTRY\\USER\\`
3. Calls kernel registry APIs:
   - `ZwOpenKey`
   - `ZwCreateKey`
   - `ZwDeleteValueKey`
   - `ZwDeleteKey`
   - `ZwQueryValueKey`
   - `ZwSetValueKey`

The critical flaw is that the driver:

- **does not** restrict the path to an IDM-owned namespace
- **does not** verify whether the caller is authorized to access the target key
- **does not** limit the operation to the caller’s own `HKCU` mapping

As a result, the interface effectively allows an ordinary user, via a kernel driver proxy, to perform arbitrary path-level registry operations under:

- `HKLM\...`
- `HKU\...`

---

## 6. Technical Details

### 6.1 Relevant IOCTL

Main command:

- `0x12C028`

Subcommands directly relevant to this vulnerability:

- `0x0C`: query value
- `0x0D`: create missing key path and set value
- `0x0E`: delete value
- `0x0F`: delete value and remove the key if it becomes empty

### 6.2 Shared Input Structure

These four subcommands use a common input format:

```c
#pragma pack(push, 1)
typedef struct IDMWFP_REG_CMD {
    uint8_t  subcmd;        // 0x0C / 0x0D / 0x0E / 0x0F
    uint8_t  mode;
    uint16_t reserved0;
    uint32_t flags;         // bit0 = HKLM, bit1 = HKU
    uint16_t path_offset;   // points to an encoded UTF-16 path
    uint16_t path_wchars;   // number of UTF-16 characters in the path
    uint16_t data_offset;   // used by 0x0D
    uint16_t data_size;     // used by 0x0D
    uint16_t value_type;    // used by 0x0D / 0x0C
    uint8_t  seed0;
    uint8_t  seed1;
    // followed by:
    //   encoded_utf16_path[path_wchars]
    //   encoded_or_raw_data[data_size]
} IDMWFP_REG_CMD;
#pragma pack(pop)
```

The path string is decoded inside the driver and split at the last `\` into:

- `key path`
- `value name`

Therefore, the attacker fully controls:

- Registry root (`HKLM` / `HKU`)
- Relative key path
- Value name
- Value type
- Value contents

### 6.3 Behavior Confirmed Dynamically

Using a custom PoC tool, I confirmed that:

1. `0x0D` writes a `REG_DWORD` to `HKLM\SOFTWARE\IDMWFPProbe2\Val`
2. `0x0C` reads the value back correctly
3. `0x0E` deletes the value
4. `0x0F` removes an empty key
5. `0x0D` writes a `REG_EXPAND_SZ`
6. `0x0C` reads back and correctly reconstructs the string data

This demonstrates that:

- The issue is not a merely theoretical “possible write”
- It is a reliably reproducible, general-purpose registry operation primitive

---

## 7. Impact Analysis

### 7.1 Arbitrary `HKLM` Writes

For a low-privileged user, arbitrary `HKLM` writes are the most dangerous capability.

This allows an attacker to tamper with:

- `HKLM\SYSTEM\CurrentControlSet\Services\...`
- High-privilege service and driver configuration
- High-privilege program startup parameters, paths, dependencies, and DLL paths
- Security product and system-policy-related values

### 7.2 Arbitrary `HKU` Access

Via the `HKU\...` root selection, an attacker can also:

- Read and write other users’ SID-backed hives
- Alter post-logon behavior in multi-user environments
- Establish stealthier persistence

### 7.3 Why This Leads to LPE

This issue is not merely “an arbitrary registry write,” but a practical LPE risk because:

- The registry is a primary configuration source for high-privilege Windows components
- Once a low-privileged user can modify registry entries trusted by a high-privilege service or driver, attacker-controlled paths, parameters, or DLL references can be inserted into a privileged execution chain

Typical scenarios include:

- Modifying an existing service’s `ImagePath`
- Modifying DLL or argument paths used by a service
- Modifying a driver service configuration and waiting for reboot or service restart
- Tampering with registry values read by `SYSTEM` or high-integrity processes

Even if a specific environment still requires a service restart, system reboot, or another trigger before a privileged component consumes the modified configuration, that remains a standard local-privilege-escalation chain.

In other words:

- The vulnerability itself provides a **high-privilege registry primitive**
- LPE is the direct security consequence of that primitive

---

## 8. Exploitation Scenarios

### Scenario A: High-Privilege Service Configuration Tampering

An ordinary user can rewrite:

- `HKLM\SYSTEM\CurrentControlSet\Services\<Target>\ImagePath`

If the target service is later started under a high-privilege context, the attacker may gain privileged code execution.

### Scenario B: Driver Service Path Tampering

An ordinary user can rewrite:

- A driver service’s `ImagePath`

On reboot or later reload, this can redirect execution to an attacker-controlled binary path.

### Scenario C: Security Configuration Damage and High-Privilege Persistence

An attacker can alter:

- Security product configuration
- Service parameters
- System component configuration

to obtain long-term persistence or reduce system protections.

---

## 9. Reproduction

### 9.1 Environment

- Windows system
- `idmwfp.sys` loaded
- Ordinary local authenticated user

### 9.2 Install IDM Normally

Install [idman642build63.exe](../poc/idman642build63.exe) from the `poc` folder. This is the latest official version. Versions released after November 2023 can use this PoC directly.

### 9.3 Run the PoC Wrapper

Run:

```powershell
.\poc.bat
```

from the `poc` directory.

This step reproduces the vendor-facing PoC workflow packaged with the project.

Note: after the PoC is triggered, the payload may be launched in a different Windows session. As a result, the program window may not appear on the current interactive desktop even if execution is successful. In such cases, the process can still be observed in Task Manager, for example as a `cmd.exe` instance running under the `SYSTEM` user.

### 9.4 Minimal PoC: Arbitrary `HKLM` Write

Use the custom tool:

- `idmwfp_reg_demo.exe`

Write a `REG_DWORD`:

```powershell
.\idmwfp_reg_demo.exe set-dword machine "SOFTWARE\IDMWFPProbe2\Val" 0x11223344
```

Read it back:

```powershell
.\idmwfp_reg_demo.exe query machine "SOFTWARE\IDMWFPProbe2\Val" 64
```

Expected output includes:

```text
decoded: title_index=16 type=4 data_len=4
value(dword)=0x11223344
```

### 9.5 Write `REG_EXPAND_SZ`

```powershell
.\idmwfp_reg_demo.exe set-expand-string machine "SOFTWARE\IDMWFPRegDemo\Path" "\SystemRoot\System32\drivers\Test.sys"
```

Read it back:

```powershell
.\idmwfp_reg_demo.exe query machine "SOFTWARE\IDMWFPRegDemo\Path" 256
```

Expected output includes:

```text
type=2
value(expand_sz)=\SystemRoot\System32\drivers\Test.sys
```

### 9.6 Delete Value and Key

```powershell
.\idmwfp_reg_demo.exe del-value machine "SOFTWARE\IDMWFPProbe2\Val"
.\idmwfp_reg_demo.exe del-key machine "SOFTWARE\IDMWFPProbe2\Val"
```

This demonstrates that:

- An ordinary user can not only write, but also remove or destroy sensitive configuration paths

### 9.7 High-Risk Path Example

For example, an attacker can attempt to write:

```powershell
.\idmwfp_reg_demo.exe set-expand-string machine "SYSTEM\CurrentControlSet\Services\<Target>\ImagePath" "\SystemRoot\System32\drivers\Attacker.sys"
```

Such paths reside under:

- `HKLM\SYSTEM\CurrentControlSet\Services\...`

and are clearly outside IDM’s legitimate configuration scope.

---

## 10. Root Cause Summary

The vulnerability requires two conditions to hold, and this driver satisfies both:

1. The device object is open to all authenticated users
2. IOCTL handlers perform privileged registry operations without authorization or namespace restrictions

In essence, this is:

- “a kernel-proxy registry interface callable by low-privileged users”

rather than:

- “a restricted interface used only for IDM-owned configuration”

---

## 11. Security Recommendations

At minimum, the following issues should be fixed:

### 11.1 Tighten the Device ACL

The driver should not use:

- `D:P(A;;GA;;;AU)`

It should instead allow only:

- Administrators
- `SYSTEM`
- An IDM-owned service SID

### 11.2 Enforce a Registry Path Whitelist

`subcmd 0x0C..0x0F` should be strictly limited to IDM-owned registry namespaces, for example:

- `HKLM\SOFTWARE\Wow6432Node\Internet Download Manager\...`
- Or another explicit, minimal allowlist defined by the vendor

The driver should never allow caller-supplied arbitrary relative paths.

### 11.3 Add Caller Authorization Checks

Even if the path falls within an allowed namespace, the driver should still validate:

- Caller SID / token
- Whether the caller is a trusted service
- Whether the caller has administrative privileges

### 11.4 Prevent Generic `HKLM` / `HKU` Access by Ordinary Users

In particular, ordinary users must not be allowed to bypass normal ACLs via a kernel driver proxy.

---

## 12. Conclusion

This is a high-severity kernel driver logic vulnerability.

`idmwfp.sys` exposes a kernel-backed registry read/write capability over arbitrary paths in `HKLM` and `HKU` to low-privileged users through an IOCTL interface open to all authenticated users.

This kind of capability alone is sufficient to be viewed as:

- A security-boundary break
- A high-risk local privilege escalation primitive
- A high-privilege persistence primitive

From a defensive perspective, this should not be downgraded to a mere “configuration issue” or “misuse of a private product interface,” because:

- The affected namespace is not IDM-owned
- The actual targets are system-level, high-value registry roots
- The issue is reproducible by an ordinary user

Therefore, the vendor should fix it as soon as possible, and ZDI should treat it as a kernel-driver vulnerability leading to local privilege escalation via arbitrary registry read/write.
