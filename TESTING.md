# 征集测试 · 填写模板

本包所有 PoC **均未经真机验证**。需要窗口内设备（iOS 27.0 / 27.0.1 / 27.1）做一次实测。

## 参与条件

- 设备：iPhone 11 及以后任意机型（A13+；ANE 那条需要 H16 及以上）
- 系统：**iOS 27.0（24A437）或 27.0.1（24A446）或 27.1（24A94425, 仅 iPhone Duo）**
  - 已升 27.2 / 27.2.1 的**无效**，漏洞已被修复
- 能 sideload 自签 app（Apple ID 免费签名即可，7 天有效期）
- 能取到 panic 日志

## 操作步骤

```sh
# 1. 编译（在 Mac 上）
cd poc && make

# 2. 签名并安装（示例，用你自己的 team id）
codesign -s "Apple Development: your@id" -f ave_oob
# 通过 Xcode / ios-deploy / AltStore 安装到设备

# 3. 设备上运行（用 SSH 或 app 内调用）
./ave_oob
./iosurface_race
./spec_race
```

## 需要回传的数据

| 项目 | 内容 |
|---|---|
| 设备型号 / 芯片 | 例：iPhone 17 Pro / A19 Pro |
| iOS 版本 + build | 例：27.0.1 (24A446) |
| `ave_oob` 输出 | 一行 `kr=0x...` 的完整内容 |
| 是否 panic | 有/无 |
| panic 文件 | `panic-full-*.ips` 全文（重点：`panicString` 与 kernel stack 前 10 帧） |
| `iosurface_race` / `spec_race` 结果 | 运行时长 + 是否有 panic |
| 若 panic，重复性 | 1 次命中 / 10 次内命中 / 从未命中 |

panic 日志取法：
```sh
idevicecrashreport -e ./crash          # 或
# 设备：设置 → 隐私与安全性 → 分析与改进 → 分析数据 → panic-full-...
```

## 判定标准

| 结果 | 含义 |
|---|---|
| `ave_oob` 返回 `0xE00002C2` (kIOReturnBadArgument) | 参数校验拦住 → 说明该版本已修，或结构体偏移不对 |
| `ave_oob` 返回 `0` 或其它值 + 无 panic | 参数被接受，但未触发越界 → 需要换更大的计数 |
| 出现 panic 且栈里有 `memcpy`/`kalloc`/AVE 函数 | **命中**，把栈发回来即可定位 |
| `IOServiceOpen` 返回 `0xE00002E2` | 沙盒 entitlement 拦截 → T1 失败，AVE 路线作废，改打 IOSurface/spec |

## 当前缺口（等这些数据才能继续）

1. T1 `AppleAVE2Driver` 是否对沙盒 app 开放
2. T2/T3 AVE 越界落点（决定能否变写原语）
3. T4 IOSurface 竞态命中率
4. T5 沙盒内可 revoke 的 spec 节点
5. T7 内核 112507/84495/112474 的真实位置
