#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <vector>
#include <thread>
#include <chrono>
#include <tlhelp32.h>
#include <psapi.h>
#include <MinHook.h>


#pragma warning (disable: 4313) // 'function' : 'format specifier' in format string conflicts with argument number of type 'type'
#pragma warning (disable: 4477) // 'function' : format string 'string' requires an argument of type 'type', but variadic argument number has type 'type'

//

typedef unsigned __int64 QWORD;

//

#ifndef NDEBUG
const bool DEBUG_ENABLED = true;
#else
const bool DEBUG_ENABLED = false;
#endif

const QWORD creditsAddr = 0x4AD350;

//

#define printfn(a,...) printf(a"\n", __VA_ARGS__)

//

void CreateConsoleWindow();
DWORD WINAPI listener(LPVOID lpReserved);

const char labelCredits[] = {

    'l', 0,
    'a', 0,
    'b', 0,
    'e', 0,
    'l', 0,
    ' ', 0,
    'c', 0,
    'r', 0,
    'e', 0,
    'd', 0,
    'i', 0,
    't', 0,
    's', 0,
};

const char rollCredits[] = {

    'r', 0,
    'o', 0,
    'l', 0,
    'l', 0,
    'c', 0,
    'r', 0,
    'e', 0,
    'd', 0,
    'i', 0,
    't', 0,
    's', 0,
    ' ', 0,
};
const char endOfLabel[] = { 0, 0, 0, 0 };


typedef void* (WINAPI* THE_VOID_TEXT)(void*, void*);
THE_VOID_TEXT origFuncCredits = NULL;
void* HOOK_Credits(void* thisptr, char* str)
{
    const int start = 20;
    const int readLength = 7800;

    int i = 0, j;
    int startPointer = 0x0;
    int changePointer = 0x0, endChangePointer = 0x0;
    int endPointer = 0x0;

    for (j = 0; j < sizeof(labelCredits); j++)
    {
        if (str[start + j] != labelCredits[j]) break;
    }

    if (j != sizeof(labelCredits))
    {
        if (DEBUG_ENABLED) printfn("Skip label | j: %d", j);

        return origFuncCredits(thisptr, str);
    }

    for (i = start; i < readLength; i++)
    {
        if (std::memcmp(rollCredits, str + i, sizeof(rollCredits)) == NULL)
        {
            startPointer = i;
            break;
        }
    }

    changePointer = startPointer + sizeof(rollCredits);

    str[changePointer] = '0';

    changePointer += 2;

    for (i = changePointer; i < readLength; i++)
    {
        if (str[i] == NULL) continue;

        if (str[i] > '9' || str[i] < '0') break;
    }

    endChangePointer = i;

    for (; i < readLength; i++)
    {
        if (std::memcmp(endOfLabel, str + i, sizeof(endOfLabel)) == NULL)
        {
            endPointer = i;
            break;
        }
    }

    int szAlloc = endPointer - endChangePointer;
    if (DEBUG_ENABLED) printfn("==== Allocated %d bytes", szAlloc);

    char* data = reinterpret_cast<char*>(malloc(szAlloc));
    if (data == nullptr)
    {
        if (DEBUG_ENABLED) printfn("Allocated failed!");

        return origFuncCredits(thisptr, str);
    }

    memcpy(data, str + endChangePointer, szAlloc);
    memcpy(str + changePointer, data, szAlloc);
    
    j = endPointer - (endChangePointer - changePointer);
    
    for (i = j; i < endPointer; i++)
    {
        if (str[i] == NULL) continue;

        str[i] = 13;
    }

    if (DEBUG_ENABLED)
    {
        printfn("\n\nTEXT:");
        for (i = start; i < endPointer; i++)
        {
            if (str[i] == NULL) continue;

            printf("%c", str[i]);
        }

        printfn("\n\nDEC:");
        for (i = start; i < endPointer; i++)
        {
            // if (str[i] == NULL) continue;

            printf("%d ", str[i]);
        }
    }

    return origFuncCredits(thisptr, str);
}

//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (DEBUG_ENABLED) CreateConsoleWindow();

            int code = MH_Initialize();

            if (code == MH_OK)
            {
                if (DEBUG_ENABLED) printfn("MH Initialized");
            }
            else
            {
                if (DEBUG_ENABLED) printfn("MH Error: %d", code);
            }

            DisableThreadLibraryCalls(hModule);
            CreateThread(nullptr, 0, listener, hModule, 0, nullptr);
            
            break;
        }

        case DLL_THREAD_ATTACH:
        {
            break;
        }

        case DLL_THREAD_DETACH:
        {
            break;
        }

        case DLL_PROCESS_DETACH:
        {
            break;
        }
    }

    return TRUE;
}

struct stHook
{
    stHook(LPVOID Address, LPVOID Detour, LPVOID* Original) : addr(Address), detour(Detour), orig(Original)
    {
    };

    LPVOID addr = 0x0;
    LPVOID detour = 0x0;
    LPVOID* orig = 0x0;
};

std::vector<stHook> hooks;          

DWORD WINAPI listener(LPVOID lpReserved)
{
    QWORD base = (QWORD)GetModuleHandleW(L"GameAssembly.dll");
    if (DEBUG_ENABLED) printfn("base: 0x%llx", base);

    hooks.push_back(stHook(reinterpret_cast<LPVOID>(base + creditsAddr), &HOOK_Credits, reinterpret_cast<LPVOID*>(&origFuncCredits))); // Novel.Game.Parsing.ScenarioParser.Parse

    int i, size = static_cast<int>(hooks.size());
    for (i = 0; i < size; i++)
    {
        if (MH_CreateHook(hooks[i].addr, hooks[i].detour, hooks[i].orig) == MH_OK)
        {
            if (DEBUG_ENABLED) printfn("MH Hook 0x%llx install", hooks[i].addr);

            if (MH_EnableHook(hooks[i].addr) == MH_OK)
            {
                if (DEBUG_ENABLED) printfn("Enabled");
            }
            else
            {
                if (DEBUG_ENABLED) printfn("Error");
            }
        }
        else
        {
            if (DEBUG_ENABLED) printfn("MH Hook 0x%llx failed", hooks[i].addr);
        }
    }

    return 1;
}

void CreateConsoleWindow()
{
    AllocConsole();

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
}