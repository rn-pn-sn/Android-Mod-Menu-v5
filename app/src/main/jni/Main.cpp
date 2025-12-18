#include <list>
#include <vector>
#include <cstring>
#include <pthread.h>
#include <thread>
#include <cstring>
#include <string>
#include <jni.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <dlfcn.h>
#include "Includes/Logger.h"
#include "Includes/obfuscate.h"
#include "Includes/Utils.hpp"
#include "Menu/Menu.hpp"
#include "Menu/Jni.hpp"
#include "Includes/Macros.h"
#include "dobby.h"

int scoreMul = 1, coinsMul = 1;

// Do not change or translate the first text unless you know what you are doing
// Assigning feature numbers is optional. Without it, it will automatically count for you, starting from 0
// Assigned feature numbers can be like any numbers 1,3,200,10... instead in order 0,1,2,3,4,5...
// ButtonLink, Category, RichTextView and RichWebView is not counted. They can't have feature number assigned
// Toggle, ButtonOnOff and Checkbox can be switched on by default, if you add True_. Example: CheckBox_True_The Check Box
// To learn HTML, go to this page: https://www.w3schools.com/

jobjectArray GetFeatureList(JNIEnv *env, jobject context) {
    jobjectArray ret;

    const char *features[] = {
            OBFUSCATE("Toggle_No death"),
            OBFUSCATE("Button_Start Invcibility (30 sec duration)"),
            OBFUSCATE("SeekBar_Score multiplier_1_100"),
            OBFUSCATE("SeekBar_Coins multiplier_1_1000"),
            OBFUSCATE("Category_Examples"), //Not counted
            OBFUSCATE("Toggle_The toggle"),
            OBFUSCATE(
                    "100_Toggle_True_The toggle 2"), //This one have feature number assigned, and switched on by default
            OBFUSCATE("110_Toggle_The toggle 3"), //This one too
            OBFUSCATE("SeekBar_The slider_1_100"),
            OBFUSCATE("SeekBar_Kittymemory slider example_1_5"),
            OBFUSCATE("Spinner_The spinner_Items 1,Items 2,Items 3"),
            OBFUSCATE("Button_The button"),
            OBFUSCATE("ButtonLink_The button with link_https://www.youtube.com/"), //Not counted
            OBFUSCATE("ButtonOnOff_The On/Off button"),
            OBFUSCATE("CheckBox_The Check Box"),
            OBFUSCATE("InputValue_Input number"),
            OBFUSCATE("InputValue_1000_Input number 2"), //Max value
			OBFUSCATE("1111_InputLValue_Input long number"),
            OBFUSCATE("InputLValue_1000000000000_Input long number 2"), //Max value
            OBFUSCATE("InputText_Input text"),
            OBFUSCATE("RadioButton_Radio buttons_OFF,Mod 1,Mod 2,Mod 3"),

            //Create new collapse
            OBFUSCATE("Collapse_Collapse 1"),
            OBFUSCATE("CollapseAdd_Toggle_The toggle"),
            OBFUSCATE("CollapseAdd_Toggle_The toggle"),
            OBFUSCATE("123_CollapseAdd_Toggle_The toggle"),
            OBFUSCATE("122_CollapseAdd_CheckBox_Check box"),
            OBFUSCATE("CollapseAdd_Button_The button"),

            //Create new collapse again
            OBFUSCATE("Collapse_Collapse 2_True"),
            OBFUSCATE("CollapseAdd_SeekBar_The slider_1_100"),
            OBFUSCATE("CollapseAdd_InputValue_Input number"),

            OBFUSCATE("RichTextView_This is text view, not fully HTML."
                      "<b>Bold</b> <i>italic</i> <u>underline</u>"
                      "<br />New line <font color='red'>Support colors</font>"
                      "<br/><big>bigger Text</big>"),
            OBFUSCATE("RichWebView_<html><head><style>body{color: white;}</style></head><body>"
                      "This is WebView, with REAL HTML support!"
                      "<div style=\"background-color: darkblue; text-align: center;\">Support CSS</div>"
                      "<marquee style=\"color: green; font-weight:bold;\" direction=\"left\" scrollamount=\"5\" behavior=\"scroll\">This is <u>scrollable</u> text</marquee>"
                      "</body></html>")
    };

    int Total_Feature = (sizeof features / sizeof features[0]);
    ret = (jobjectArray)
            env->NewObjectArray(Total_Feature, env->FindClass(OBFUSCATE("java/lang/String")),
                                env->NewStringUTF(""));

    for (int i = 0; i < Total_Feature; i++)
        env->SetObjectArrayElement(ret, i, env->NewStringUTF(features[i]));

    return (ret);
}

bool btnPressed = false;

//Target main lib here
#define targetLibName OBFUSCATE("libil2cpp.so")

void Changes(JNIEnv *env, jclass clazz, jobject obj, jint featNum, jstring featName, jint value, jlong Lvalue, jboolean boolean, jstring text) {

    switch (featNum) {
        case 0:
            // offset, hex
            PATCH_SWITCH(targetLibName, "0x1079728", "C0 03 5F D6", boolean);
            // The patch switch has been returned and reworked... so it should work stably
            // if you encounter any problems:
            // - uncommiting logging for detailed checking of your functions;
            // - special attention to the preferences -> this is the only source of this problem in the past that I have noticed:
            // -- try rename the preferences file;
            // -- for a stable and more flexible save settings, recommend using own system with XML/JSON files.

            // alt possibles usage variants:
            // symbol, hex
            PATCH_SWITCH(targetLibName, "_example__sym", "C0 03 5F D6", boolean);
            // offset, asm
            PATCH_SWITCH(targetLibName, "0x1079728", "ret", boolean);
            // symbol, asm
            PATCH_SWITCH(targetLibName, OBFUSCATE("_example__sym"), OBFUSCATE("ret"), boolean);

            // asm allows you to avoid using hex code, as it is generated automatically from the instructions.
            // - this is the awesome option if you know what you're doing
            // - this is probably especially useful with creating dynamic deep patches

            // recommended insert ';' to separate statements, example: "mov x0, #1; ret"
            // recommended to test your instructions on https://armconverter.com or
            // https://shell-storm.org/online/Online-Assembler-and-Disassembler/
            break;
        case 4:
            if(boolean) {
                // offset, hex
                PATCH(targetLibName, OBFUSCATE("0x10709AC"), OBFUSCATE("E05F40B2 C0035FD6"));

                // alt possibles usage variants:
                // symbol, hex
                PATCH(targetLibName, OBFUSCATE("_example__sym"), OBFUSCATE("E0 5F 40 B2 C0 03 5F D6"));
                // offset, asm
                PATCH(targetLibName, OBFUSCATE("0x10709AC"), OBFUSCATE("mov x0, #0xffffff; ret"));
                // symbol, asm
                PATCH(targetLibName, OBFUSCATE("_example__sym"), OBFUSCATE("mov x0, #0xffffff; ret"));
            } else {
                RESTORE(targetLibName, OBFUSCATE("0x10709AC"));
                // or
                RESTORE(targetLibName, OBFUSCATE("_example__sym"));
            }
            break;
        case 1:
            btnPressed = true;
            break;
        case 2:
            scoreMul = value;
            break;
        case 3:
            coinsMul = value;
            break;
        default:
            break;
    }
}

//CharacterPlayer
void (*StartInvcibility)(void *instance, float duration);

void (*old_Update)(void *instance);
void Update(void *instance) {
    if (instance != nullptr) {
        if (btnPressed) {
            StartInvcibility(instance, 30);
            btnPressed = false;
        }
    }
    return old_Update(instance);
}

/*
 void (*old_AddScore)(void *instance, int score);
 void AddScore(void *instance, int score) {
    //default any actions
    return old_AddScore(instance, score * scoreMul);
 }
*/
// === This function was completely replaced with super-macro `install_hook_name` from dobby.h ===
// (base name, return type, ... args)
install_hook_name(AddScore, void *, void *instance, int score) {
    // default any actions

    // use orig_ for call original function
    return orig_AddScore(instance, score + scoreMul);
}

void (*old_AddCoins)(void *instance, int count);
void AddCoins(void *instance, int count) {
    return old_AddCoins(instance, count * coinsMul);
}


// we will run our hacks in a new thread so our while loop doesn't block process main thread
void hack_thread() {
    // This loop should be always enabled in unity game
    // because libil2cpp.so is not loaded into memory immediately.
    while (!isLibraryLoaded(targetLibName)) {
        sleep(1); // Wait for target lib be loaded.
    }

    // In Android Studio, to switch between arm64-v8a and armeabi-v7a syntax highlighting,
    // You can modify the "Active ABI" in "Build Variants" to switch to another architecture for parsing.
#if defined(__aarch64__)
    //Il2Cpp: Use RVA offset
    StartInvcibility = (void (*)(void *, float)) getAbsoluteAddress(targetLibName, OBFUSCATE("0x107A3BC"));
    // StartInvcibility = (void (*)(void *, float)) getAbsoluteAddress(targetLibName, "_characterPlayer_Update"));

    HOOK(targetLibName, OBFUSCATE("0x107A2FC"), AddCoins, old_AddCoins);

    // HOOK(targetLibName, OBFUSCATE("0x107A2E0"), AddScore, old_AddScore);
    // === This function was completely replaced with super-macro `install_hook_name` from dobby.h ===
    // don't forget set address for hook super-macro:
    install_hook_AddScore(getAbsoluteAddress(targetLibName,OBFUSCATE("0x107A2E0")));

    HOOK(targetLibName, OBFUSCATE("0x1078C44"), Update, old_Update);
    //HOOK(targetLibName, OBFUSCATE("0x1079728"), Kill, old_Kill);
    //HOOK(targetLibName, OBFUSCATE("_example__sym"), Kill, old_Kill);
    //HOOK_NO_ORIG("libFileC.so", OBFUSCATE("0x123456"), FunctionExample);
    //HOOK_NO_ORIG("libFileC.so", OBFUSCATE("_example__sym"), FunctionExample);

    //PATCH(targetLibName, OBFUSCATE("0x10709AC"), "E05F40B2C0035FD6");

    // you can use this for things as detect log, counting function calls, executing side code before the function is executed
    // now instrument wrapper implemented for detecting execution
    INST(targetLibName, OBFUSCATE("0x23558C"), OBFUSCATE("AnyNameForDetect"));
    INST(targetLibName, OBFUSCATE("0x235630"), OBFUSCATE("AnyNameForDetect2"));
    INST(targetLibName, OBFUSCATE("_example__sym"), OBFUSCATE("AnyNameForDetect3"));

    // LOGI("Test SYM: 0x%llx", (uintptr_t)getAbsoluteAddress(targetLibName, "il2cpp_init"));
#elif defined(__arm__)
    //Put your code here if you want the code to be compiled for armv7 only
#endif

    LOGI(OBFUSCATE("Done"));
}

// Functions with `__attribute__((constructor))` are executed immediately when System.loadLibrary("lib_name") is called.
// If there are multiple such functions at the same time, `constructor(priority)` (the priority is an integer)
// will determine the execution priority, otherwise the execution order is undefined behavior.
__attribute__((constructor))
void lib_main() {
    // Create a new thread so it does not block the main thread, means the game would not freeze
    // In modern C++, you should use std::thread(yourFunction).detach() instead of pthread_create
    std::thread(hack_thread).detach();
}