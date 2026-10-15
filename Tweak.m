#import <Foundation/Foundation.h>
#import "CydiaSubstrate.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "MappingPatch.h"

static const char *kGate = "/var/tmp/aime-classic-listen-probe.enabled";
static const char *kFelicaGate = "/var/tmp/aime-felica-host-probe.enabled";
static uintptr_t (*originalConfigMapping)(uintptr_t, uint32_t, const AimeDiscMapEntry *, uintptr_t, uintptr_t);
static uintptr_t (*originalConfigSequence)(uintptr_t, uintptr_t, uintptr_t);
static uintptr_t (*originalActivationParser)(uintptr_t, uintptr_t, uintptr_t);
static uintptr_t (*originalProtoIfMapRsp)(uintptr_t);
static uintptr_t (*originalSetCEConfig)(uintptr_t, const uint8_t *, uintptr_t, uintptr_t);
static uintptr_t (*originalSetCEConfigProc)(uintptr_t, uintptr_t);
static id (*originalHostCardEmulationConfig)(id, SEL, BOOL);

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

static uintptr_t setCEConfig(uintptr_t handle, const uint8_t *config,
                             uintptr_t callback, uintptr_t callbackContext) {
    if (!config || access(kFelicaGate, F_OK) != 0)
        return originalSetCEConfig(handle, config, callback, callbackContext);
    uint32_t type = 0;
    memcpy(&type, config + 4, sizeof(type));
    record("ce_original_type", type);
    if (type != 1 && type != 2)
        return originalSetCEConfig(handle, config, callback, callbackContext);

    // The validated Comet CE union is at least 0x4a bytes. Type 4 consumes
    // only offsets 4, 9..16, 0x16..0x1b and 0x1c..0x1d.
    uint8_t patched[0x50] = {0};
    const uint32_t felica = 4;
    const uint8_t idm[8] = {0x02,0xfe,0x00,0x00,0x00,0x00,0x00,0x01};
    const uint8_t pmmSuffix[6] = {0,0,0,0,0,0};
    const uint8_t wildcardSystem[2] = {0xff,0xff};
    memcpy(patched + 4, &felica, sizeof(felica));
    memcpy(patched + 9, idm, sizeof(idm));
    memcpy(patched + 0x16, pmmSuffix, sizeof(pmmSuffix));
    memcpy(patched + 0x1c, wildcardSystem, sizeof(wildcardSystem));
    record(type == 1 ? "ce_type_1_to_4" : "ce_type_2_to_4", felica);
    return originalSetCEConfig(handle, patched, callback, callbackContext);
}

static uintptr_t setCEConfigProc(uintptr_t context, uintptr_t status) {
    record("ce_config_result", status);
    return originalSetCEConfigProc(context, status);
}

static id hostCardEmulationConfig(id cls, SEL selector, BOOL fieldDetect) {
    id config = originalHostCardEmulationConfig(cls, selector, fieldDetect);
    if (!config || access(kFelicaGate, F_OK) != 0) return config;
    void *opaque = (__bridge void *)config;
    uint8_t *bytes = opaque;
    int32_t cardType = 0;
    uint64_t hostMode = 0, embeddedMode = 0;
    memcpy(&cardType, bytes + 0x10, sizeof(cardType));
    memcpy(&hostMode, bytes + 0x20, sizeof(hostMode));
    memcpy(&embeddedMode, bytes + 0x28, sizeof(embeddedMode));
    record("routing_original_card_type", (unsigned long)cardType);
    record("routing_original_host_mode", (unsigned long)hostMode);
    record("routing_original_embedded_mode", (unsigned long)embeddedMode);
    if (cardType == 3 && hostMode == 2 && embeddedMode == 0) {
        const int32_t felicaCardType = 4;
        memcpy(bytes + 0x10, &felicaCardType, sizeof(felicaCardType));
        record("routing_card_type_3_to_4", felicaCardType);
    }
    return config;
}

__attribute__((constructor)) static void start(void) {
    @autoreleasepool {
        BOOL classicEnabled = access(kGate, F_OK) == 0;
        BOOL felicaEnabled = access(kFelicaGate, F_OK) == 0;
        if (![[NSProcessInfo processInfo].processName isEqualToString:@"nfcd"] || (!classicEnabled && !felicaEnabled)) return;
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
        void *ceConfigProc = (uint8_t *)entry - 0x2112c;
        MSHookFunction(activation, (void *)activationParser, (void **)&originalActivationParser);
        if (classicEnabled) {
            MSHookFunction(mappingResponse, (void *)protoIfMapRsp, (void **)&originalProtoIfMapRsp);
            MSHookFunction(sequence, (void *)configSequence, (void **)&originalConfigSequence);
            MSHookFunction(target, (void *)configMapping, (void **)&originalConfigMapping);
        }
        if (felicaEnabled) {
            void *setCE = dlsym(RTLD_DEFAULT, "phLibNfc_Mgt_SetCE_ConfigParams");
            if (setCE) MSHookFunction(ptrauth_strip(setCE, ptrauth_key_function_pointer),
                                      (void *)setCEConfig, (void **)&originalSetCEConfig);
            MSHookFunction(ceConfigProc, (void *)setCEConfigProc, (void **)&originalSetCEConfigProc);
            Class routingClass = objc_getClass("NFRoutingConfig");
            Method routingFactory = routingClass ? class_getClassMethod(routingClass,
                sel_registerName("hostCardEmulationWithFieldDetect:")) : NULL;
            if (routingFactory) MSHookFunction((void *)method_getImplementation(routingFactory),
                (void *)hostCardEmulationConfig, (void **)&originalHostCardEmulationConfig);
        }
        BOOL ok = originalActivationParser &&
            (!classicEnabled || (originalConfigMapping && originalConfigSequence && originalProtoIfMapRsp)) &&
            (!felicaEnabled || (originalSetCEConfig && originalSetCEConfigProc && originalHostCardEmulationConfig));
        record(ok ? "hooks_installed" : "hook_failed", (unsigned long)target);
    }
}
