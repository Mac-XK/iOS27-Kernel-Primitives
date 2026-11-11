# iOS 27.0–27.1 越狱研究包

> 目标：自研 Dopamine 式越狱的第一步——拿到可用的内核内存破坏原语。
> 本包只含**已用二进制 diff 实证**的东西，不含推测性 CVE 罗列。

---

## 1. 结论摘要

| # | 组件 | CVE（27.2 修复） | 原语 | 证据强度 | PoC |
|---|---|---|---|---|---|
| 1 | AppleAVE2 | 2026-112466/468/469/470/705/689 | 内核 OOB write（码流参数越界） | ★★★ 校验层 diff + 边界反证 | `ave_oob` |
| 2 | IOSurface | 2026-112477 | 内核 UAF（摘除-重插竞态） | ★★★ 修复位定位 | `iosurface_race` |
| 3 | Kernel spec_vnops | 27.2 新增 revoke 门禁 | 内核 UAF（revoke 竞态） | ★★★ 汇编级 diff | `spec_race` |
| 4 | AppleH16ANE | 2026-112696 / 84494 | 内核 OOB write（描述符索引） | ★★☆ 校验点定位，字段未全定 | `ane_oob` |
| 5 | com.apple.kernel | 112507 / 84495 / 112474 等 | 未知（公告级） | ★☆☆ 未定位 | — |

**窗口**：iOS 27.0 = 27.0.1（27.0.1 无安全条目），27.1 仅 iPhone Duo。**27.2 已全部修掉**，27.2.1 再修 9 条。
iPhone 17/18 系列是 27.0 → 27.2 直跳，没有 27.1。

---

## 2. 关键技术数据

### 2.1 AppleAVE2（主攻）

驱动：`com.apple.driver.AppleAVE2`，服务名 `AppleAVE2Driver`，客户端 `AppleAVE2UserClient`。

外部方法表（27.2，dispatch `0xfffffe0008965a08`，表 `0xfffffe0007fe18d0`，步长 0x28）：

| sel | handler | struct_in | 用途 |
|---|---|---|---|
| 1 | 0x8965c20 | 0x768 | 小配置 |
| 4 | **0x89677fc** | **0x12C10** | session config → CheckCodecInfo |
| 5 | 0x89682d8 | 0x12C20 | 另一条 session 路径 |
| 6–10 | 0x8968e1c 起 | 0x30 | 逐帧/参数 |
| 11–15 | 0x896b6a8 起 | 0 | 无参命令 |

调用链：`sel4 → Prepare(0x8967e10) → 0x882a694 → 0x8824cc4 → 0x8824338(CheckCodecInfo) → 0x8820e00`，
`0x8820e00` 按 `params+0x58` 分发：1=AVC / 2=HEVC / 3=AV1。

**字段偏移**（params 基址 = 用户缓冲区 + 0x18）：

| 字段 | params | 用户缓冲区 | 27.2 校验 |
|---|---|---|---|
| codec_type | +0x58 | **0x70** | 1/2/3 |
| view number | +0x64 | **0x7C** | `(x-1) < 2` → {1,2} |
| layer number | +0x68 | **0x80** | 同上 |
| AV1 frame dimension | +0x4F8 | **0x510** | 仅下界 ≥1，**无上界** |
| AV1 MCTF strength count | +0xE70 | **0xE88** | `CMP #3` |
| HEVC frame dimension | +0xCB0 | **0xCC8** | 仅下界 |
| AVC frame dim / log2_max | +0x1896 / +0x189E | **0x18AE / 0x18B6** | u16 字段 |

**为什么值得打**：view/layer 合法域只有 2 个值 → 被当**2 元素数组下标**用；27.1 上给 0x40 即下标 64，越界 62 个元素。frame dimension 只校验下界，上界无限 → 后续 stride/size 计算存在整数溢出空间。

### 2.2 IOSurface

27.2 在 surface 对象 **+0xF1** 新增 teardown 位：
```c
// 插入路径（27.2）
if ( (*(_BYTE *)(a4 + 241) & 1) != 0 ) return 0xE00002D8;
// 摘除路径（27.2）
*(_BYTE *)(a2 + 241) = 1;   // 先置位再拆链
```
27.1 无此位 → 摘除过程中 surface 仍可被 lookup/insert 重新挂回，随后释放 → 链表悬垂 → UAF。

### 2.3 spec_vnops

27.2 在 spec ioctl 派发前新增：
```asm
LDR  X16, [vnode,#0xD8]!     ; 后端对象（PAC，AUTDA）
LDRB W9,  [X16,#0x70]
TBNZ W9,  #4, ret_ENXIO     ; 已 revoke → 拒绝派发
LDRB W9,  [vnode,#0x71]      ; spec 类型
...  _X8 = 56 * (dev >> 24)  ; major(dev) 索引 speclist
```
27.1 无此门禁 → 后端 revoke 后仍可派发到已释放结构。
索引本身安全（major 8 位，表 256 项），因此**性质是 UAF，不是越界**。

---

## 3. PoC 使用

```sh
cd poc && make          # 产出 4 个 arm64 可执行文件
```
| 程序 | 目标 | 运行 | 成功判据 |
|---|---|---|---|
| `ave_oob` | AVE2 OOB write | `./ave_oob` | 27.1 上 kr 非 0xE00002C2；27.2 上被参数校验拒绝 |
| `iosurface_race` | IOSurface UAF | `./iosurface_race` | 出现 IOSurface 相关 panic 栈 |
| `spec_race` | spec revoke UAF | `./spec_race [/dev/节点]` | 出现 spec_vnops 相关 panic |
| `ane_oob` | ANE OOB | `./ane_oob` | selector 未定，先看 kr |

所有 PoC 都是**骨架**：入口、结构体、偏移已就位，selector/触发动作按注释里的 IDA 方法补。

---

## 4. 待测试清单（当前无人验证）

这些点**全部没有实测**，是本包最大的空缺：

| 编号 | 待验证 | 需要什么 | 判定 |
|---|---|---|---|
| T1 | 沙盒 app 能否 `IOServiceOpen("AppleAVE2Driver")` | 一台 27.0/27.0.1 真机 + 自签 app | kr 是 0 还是 0xE00002E2 |
| T2 | `ave_oob` 的越界值是否真的进入 OOB 路径 | 同上 | panic 栈落在 memcpy / kalloc / firmware buffer |
| T3 | `view/layer` 越界写的是哪个数组（元素大小、相邻对象） | panic 栈 + 内存布局 | 能定位基址即可做定向写 |
| T4 | `iosurface_race` 在真机/vphone 的命中率 | 27.0/27.1 设备 | 是否出 panic |
| T5 | 沙盒内可 revoke 的 spec 节点（ptmx？） | 27.0/27.1 设备 | `spec_race` 是否命中 |
| T6 | ANE 的 selector 与 ANE 资源申请前置条件 | 27.0/27.1 设备 | `ane_oob` 是否能走进描述符解析 |
| T7 | 27.2 那 163 条里 112507/84495/112474 的实际位置 | 解密内核 + 符号，或真机 panic | 对不上名字就只能是公告级 |

**最低可推进条件**：一台 iOS 27.0 或 27.0.1 设备，能装自签 app，能回传 `panic-full-*.ips`。
没有的话，本包只能停在静态结论。

---

## 5. 明确的边界

- 本包给的是**内核内存破坏原语**，不是越狱。
- 27.x 有 SPTM/TXM + MIE：内核代码页与页表不可写，最终只能走 **data-only**（改 task/proc 数据）路线。
- tweak 注入/持久化需要 TXM trustcache 绕过，**目前无公开路径**，不包含在本包内。
- vphone 虚拟机可测 IOSurface / spec 路径（无 AVE/ANE 硬件），但它的 JB 是离线 patch 固件，不能证明零售机可行。

---

## 6. 文件清单

```
iOS27_JB_Kit/
├── README.md                      本文件
├── TESTING.md                     征集测试的填写模板
└── poc/
    ├── Makefile
    ├── ave_av1_oob.c        ave_oob       AVE2 OOB write
    ├── iosurface_teardown_race.c  iosurface_race  IOSurface UAF
    ├── spec_ioctl_revoke_race.c   spec_race       spec revoke UAF
    └── ane_procedure_oob.c  ane_oob       ANE OOB（骨架）
```
