// thanks to shmoo and joeyjurjens for the useful stuff under this comment.
#ifndef ANDROID_MOD_MENU_MACROS_H
#define ANDROID_MOD_MENU_MACROS_H

#include "KittyMemory/MemoryPatch.hpp"
#include "KittyMemory/KittyInclude.hpp"
#include "KittyMemory/Deps/Keystone/includes/keystone.h"
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




/// Dobby-Kitty patch implementation
std::map<std::string, std::tuple<void*, std::vector<uint8_t>, size_t>> pExpress;
void DobbyPatchWrapper(const char *libName, const char *relative, std::string data, bool apply) {
    std::string key = relative;
    auto it = pExpress.find(key);
    void* abs = nullptr;
    std::vector<uint8_t> patch_code;
    size_t patch_size = 0;

    if(it != pExpress.end()) {
        abs = std::get<0>(it->second);
        patch_code = std::get<1>(it->second);
        patch_size = std::get<2>(it->second);
        // LOGI(OBFUSCATE("%s <- expressed"), relative);
    } else {
        abs = getAbsoluteAddress(libName, relative);
        pExpress[key] = std::make_tuple(abs, patch_code, patch_size);
        // LOGI(OBFUSCATE("expressing %s -> new abs: 0x%llx"), relative, abs);
    }

    if(apply) {
        if(patch_code.empty()) {
            std::string asm_data = data;
            if (KittyUtils::String::ValidateHex(data)) {
                patch_size = data.length() / 2;
                patch_code.resize(patch_size);
                KittyUtils::dataFromHex(data, patch_code.data());
                // LOGI(OBFUSCATE("expressing %s -> new hex patch: %llx, %zu"), relative, patch_code.data(), patch_size);
            } else {
                ks_engine *ks = nullptr;
                ks_err err = (MP_ASM == 1) ? ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks)
                                           : ks_open(KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN, &ks);

                if (err != KS_ERR_OK) {
                    KITTY_LOGE(OBFUSCATE("ks_open failed: %s"), ks_strerror(err));
                    return;
                }

                unsigned char *insn_bytes = nullptr;
                size_t insn_size = 0, insn_count = 0;

                if (ks_asm(ks, asm_data.c_str(), 0, &insn_bytes, &insn_size, &insn_count) == 0 &&
                    insn_bytes != nullptr && insn_size > 0) {
                    patch_size = insn_size;
                    patch_code.resize(patch_size);
                    memcpy(patch_code.data(), insn_bytes, patch_size);
                }

                if (insn_bytes) ks_free(insn_bytes);
                ks_close(ks);

                // LOGI(OBFUSCATE("expressing %s -> new asm patch: %llx, %zu"), relative, patch_code.data(), patch_size);
            }
            pExpress[key] = std::make_tuple(abs, patch_code, patch_size);
        }

        if(!patch_code.empty()) {
            DobbyCodePatch(abs, patch_code.data(), patch_size);
            // LOGI(OBFUSCATE("New patch created: %s"), relative);
        } else {
            LOGE(OBFUSCATE("Failed to create patch: %s"), relative);
        }
    } else {
        DobbyDestroy(abs);
        // LOGI(OBFUSCATE("Patch removed: %s"), relative);
    }
}

/* use this if for some reason Dobby doesn't suit you:
/// KittyMemory patch implementation
std::map<const char*, MemoryPatch> memoryPatches;
void KittyPatchWrapper(const char *libName, const char *relative, std::string data, bool apply) {
    auto it = memoryPatches.find(relative);

    if(apply) {
        if(it != memoryPatches.end()) {
            MemoryPatch& existingPatch = it->second;
            if(!existingPatch.Modify()) {
                LOGE(OBFUSCATE("Failed to modify existing patch: %s"), relative);
                return;
            }
            // LOGI(OBFUSCATE("Existing patch modified: %s"), relative);
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
                LOGE(OBFUSCATE("Failed to create patch at: %s"), relative);
                return;
            }
            if(!patch.Modify()) {
                LOGE(OBFUSCATE("Failed to apply patch at: %s"), relative);
                return;
            }
            memoryPatches[relative] = patch;
            // LOGI(OBFUSCATE("New patch applied: %s"), relative);
        }
    } else {
        if(it != memoryPatches.end()) {
            if(!it->second.Restore()) {
                LOGE(OBFUSCATE("Failed to remove patch: %s"), relative);
                return;
            }
            // LOGI(OBFUSCATE("Patch removed: %s"), relative);
        }
    }
}
*/

/// classic patch (offset || sym) (hex || asm)
#define PATCH(lib, off_sym, hex_asm) DobbyPatchWrapper(lib, off_sym, hex_asm, true)
/// patch original restore (offset || sym) (hex || asm)
#define RESTORE(lib, off_sym) DobbyPatchWrapper(lib, off_sym, "", false)

/// patch switch (offset || sym) (hex || asm)
#define PATCH_SWITCH(lib, off_sym, hex_asm, boolean) DobbyPatchWrapper(lib, off_sym, hex_asm, boolean)

#endif //ANDROID_MOD_MENU_MACROS_H