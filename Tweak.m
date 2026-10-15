#import <Foundation/Foundation.h>
#import "CydiaSubstrate.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "MappingPatch.h"

static const char *kGate = "/var/tmp/aime-classic-listen-probe.enabled";
static uintptr_t (*originalConfigMapping)(uintptr_t, uint32_t, const AimeDiscMapEntry *, uintptr_t, uintptr_t);
static uintptr_t (*originalConfigSequence)(uintptr_t, uintptr_t, uintptr_t);
static uintptr_t (*originalActivationParser)(uintptr_t, uintptr_t, uintptr_t);
static uintptr_t (*originalProtoIfMapRsp)(uintptr_t);

static void record(const char *event, unsigned long value) {
    int fd = open("/var/tmp/aime-classic-listen-probe.log",
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size < 65536) {
        struct timeval now;
        gettimeofday(&now, NULL);
        char line[192];
        int length = snprintf(line, sizeof(line), "%lld.%06d pid=%d %s 0x%lx\n",
                              (long long)now.tv_sec, (int)now.tv_usec, getpid(), event, value);
        if (length > 0 && (size_t)length < sizeof(line)) (void)write(fd, line, (size_t)length);
    }
    close(fd);
}

static BOOL expectedImage(void *base) {
    const uint8_t expected[] = {0x37,0x81,0x4e,0xc4,0x42,0x54,0x31,0x50,0x90,0x3f,0x99,0xe8,0x5c,0xf0,0x6b,0x27};
    const struct mach_header_64 *header = base;
    if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 512 || header->sizeofcmds > 65536) return NO;
    const uint8_t *command = (const uint8_t *)(header + 1), *end = command + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (command + 8 > end) return NO;
        const struct load_command *load = (const void *)command;
        if (load->cmdsize < 8 || command + load->cmdsize > end) return NO;
        if (load->cmd == LC_UUID && load->cmdsize == sizeof(struct uuid_command))
            return memcmp(((const struct uuid_command *)load)->uuid, expected, sizeof(expected)) == 0;
        command += load->cmdsize;
    }
    return NO;
}

static uintptr_t configMapping(uintptr_t context, uint32_t count,
                               const AimeDiscMapEntry *entries,
                               uintptr_t callback, uintptr_t callbackContext) {
    AimeDiscMapEntry patched[2];
    if (access(kGate, F_OK) == 0 && AimePatchClassicListen(count, entries, patched)) {
        record("classic_mode_1_to_2", count);
        uintptr_t status = originalConfigMapping(context, count, patched, callback, callbackContext);
        record("config_mapping_return", status);
        return status;
    }
    return originalConfigMapping(context, count, entries, callback, callbackContext);
}

static uintptr_t configSequence(uintptr_t context, uintptr_t response, uintptr_t status) {
    record("config_mapping_response", status);
    return originalConfigSequence(context, response, status);
}

static uintptr_t protoIfMapRsp(uintptr_t context) {
    uint32_t length = 0;
    uintptr_t bytes = 0;
    if (context) {
        memcpy(&length, (const void *)(context + 0xd58), sizeof(length));
        memcpy(&bytes, (const void *)(context + 0xd50), sizeof(bytes));
    }
    record("proto_if_map_length", length);
    if (bytes && length) {
        uint8_t status = 0xff;
        memcpy(&status, (const void *)bytes, sizeof(status));
        record("proto_if_map_status_byte", status);
    }
    uintptr_t result = originalProtoIfMapRsp(context);
    record("proto_if_map_result", result);
    return result;
}

static uintptr_t activationParser(uintptr_t context, uintptr_t output, uintptr_t raw) {
    if (raw) {
        uint32_t interface = 0, technologyMode = 0, protocol = 0, discoveryMode = 0;
        memcpy(&interface, (const void *)(raw + 4), sizeof(interface));
        memcpy(&technologyMode, (const void *)(raw + 0xc), sizeof(technologyMode));
        memcpy(&protocol, (const void *)(raw + 0x10), sizeof(protocol));
        memcpy(&discoveryMode, (const void *)(raw + 0x14), sizeof(discoveryMode));
        if (protocol == 0x80 || discoveryMode == 0x80) {
            record("activation_interface", interface);
            record("activation_technology_mode", technologyMode);
            record("activation_protocol", protocol);
            record("activation_discovery_mode", discoveryMode);
        }
    }
    return originalActivationParser(context, output, raw);
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        if (![[NSProcessInfo processInfo].processName isEqualToString:@"nfcd"] || access(kGate, F_OK) != 0) return;
        void *exported = dlsym(RTLD_DEFAULT, "phLibNfc_RemoteDev_Transceive");
        Dl_info owner = {0};
        if (!exported || !dladdr(exported, &owner) || !owner.dli_fbase || !owner.dli_fname ||
            strcmp(strrchr(owner.dli_fname, '/') ? strrchr(owner.dli_fname, '/') + 1 : owner.dli_fname,
                   "libNFC_Comet.dylib") || !expectedImage(owner.dli_fbase)) {
            record("image_rejected", 0);
            return;
        }
        void *entry = ptrauth_strip(exported, ptrauth_key_function_pointer);
        void *target = (uint8_t *)entry + 0x408d0;
        void *sequence = (uint8_t *)entry + 0x394ac;
        void *mappingResponse = (uint8_t *)entry + 0x389d0;
        void *activation = (uint8_t *)entry + 0x1e214;
        MSHookFunction(activation, (void *)activationParser, (void **)&originalActivationParser);
        MSHookFunction(mappingResponse, (void *)protoIfMapRsp, (void **)&originalProtoIfMapRsp);
        MSHookFunction(sequence, (void *)configSequence, (void **)&originalConfigSequence);
        MSHookFunction(target, (void *)configMapping, (void **)&originalConfigMapping);
        record(originalConfigMapping && originalConfigSequence && originalActivationParser && originalProtoIfMapRsp ? "hooks_installed" : "hook_failed",
               (unsigned long)target);
    }
}
