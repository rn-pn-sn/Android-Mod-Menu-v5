// thanks to shmoo and joeyjurjens for the useful stuff under this comment.
#ifndef ANDROID_MOD_MENU_MACROS_H
#define ANDROID_MOD_MENU_MACROS_H

#include "KittyMemory/MemoryPatch.hpp"
#include "KittyMemory/KittyInclude.hpp"
#include "Dobby/dobby.h"

#if defined(__aarch64__)
int MP_ASM = 1;
#else
int MP_ASM = 0;
#endif

/// classic hook (offset || sym)
#define HOOK(lib, off_sym, ptr, orig) DobbyHookWrapper(lib, off_sym, (void*)(ptr), (void**)&(orig))
/// hook (offset || sym) without original
#define HOOK_NO_ORIG(lib, off_sym, ptr) DobbyHookWrapper(lib, off_sym, (void*)(ptr), nullptr)

void DobbyHookWrapper(const char *lib, const char *relative, void* hook_function, void** original_function) {
    void *abs = getAbsoluteAddress(lib, relative);

    // LOGI(OBFUSCATE("Off: 0x%llx, Addr: 0x%llx"), offset, (uintptr_t) abs);

    if (original_function != nullptr) {
        DobbyHook(abs, (dobby_dummy_func_t)hook_function, (dobby_dummy_func_t*)original_function);
    } else {
        DobbyHook(abs, (dobby_dummy_func_t)hook_function, nullptr);
    }
}

/// (offset || sym) you can use instrument for logging, counting function calls, executing side code before the function is executed
#define INST(lib, off_sym, name) DobbyInstrumentWrapper(lib, off_sym, name)

std::map<void*, const char*> detecting_functions;
void Detector(void *address, DobbyRegisterContext *ctx) {
    if(detecting_functions.count(address)) LOGW(OBFUSCATE("()0_0) %s >>>>>>>>>>>>> execute detected"), detecting_functions[address]);
}

/// an example of a wrapper with a function for detecting execution
void DobbyInstrumentWrapper(const char *lib, const char *relative, const char *name) {
    void *abs = getAbsoluteAddress(lib, relative);
    detecting_functions[abs] = name;

    // not access to the arguments "directly," as in a hook
    // accessing the arguments requires low-level register reading
    DobbyInstrument(abs, (dobby_instrument_callback_t)(Detector));
}

std::map<const char*, MemoryPatch> memoryPatches;
void patchOffsetWrapper(const char *libName, const char *relative, std::string data, bool change) {
    auto it = memoryPatches.find(relative);

    if(change) {
        if(it != memoryPatches.end()) {
            MemoryPatch& existingPatch = it->second;
            if(!existingPatch.Modify()) {
                LOGE(OBFUSCATE("Failed to modify existing patch at: %s"), relative);
                return;
            }
            // LOGI(OBFUSCATE("Existing patch modified at: %s"), relative);
        } else {
            MemoryPatch patch;
            auto address = (uintptr_t) getAbsoluteAddress(libName, relative);
            // LOGI(OBFUSCATE("Rel: %s, Addr: 0x%llx"), relative, address);

            std::string asm_data = data;
            if(KittyUtils::String::ValidateHex(data)) {
                patch = MemoryPatch::createWithHex(address, data);
            } else {
                patch = MemoryPatch::createWithAsm(address, MP_ASM_ARCH(MP_ASM), asm_data, 0);
            }

            if(!patch.isValid()) {
                LOGE(OBFUSCATE("Failed to create patch at: 0x%llx"), address);
                return;
            }
            if(!patch.Modify()) {
                LOGE(OBFUSCATE("Failed to apply patch at: 0x%llx"), address);
                return;
            }
            memoryPatches[relative] = patch;
            // LOGI(OBFUSCATE("New patch applied at: %s"), relative);
        }
    } else {
        if(it != memoryPatches.end()) {
            if(!it->second.Restore()) {
                LOGE(OBFUSCATE("Failed to restore patch at: %s"), relative);
                return;
            }
            // LOGI(OBFUSCATE("Patch restored at: %s"), relative);
        }
    }
}

/// classic patch (offset || sym) (hex || asm)
#define PATCH(lib, off_sym, hex_asm) patchOffsetWrapper(lib, off_sym, hex_asm, true)
/// patch original restore (offset || sym) (hex || asm)
#define RESTORE(lib, off_sym) patchOffsetWrapper(lib, off_sym, "", false)

/// patch switch (offset || sym) (hex || asm)
#define PATCH_SWITCH(lib, off_sym, hex_asm, boolean) patchOffsetWrapper(lib, off_sym, hex_asm, boolean)

#endif //ANDROID_MOD_MENU_MACROS_H