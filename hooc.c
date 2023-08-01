#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <tchar.h>
#include <strsafe.h>
#include <Windows.h>

#define _ASM_OP_PUSHAD 0x60
#define _ASM_OP_PUSHFD 0x9C
#define _ASM_OP_POPAD 0x61
#define _ASM_OP_POPFD 0x9D
#define _ASM_OP_CALL 0xE8
#define _ASM_OP_JMP 0xE9
#define _ASM_OP_NOP 0x90
#define _ASM_OP_RET 0xC3

#define HOOK_SIZE 6
#define TRAMPOLINE_SIZE (HOOK_SIZE + 14)

uint32_t CreateTrampoline(LPVOID lpfnTarget, LPVOID lpfnHook, LPBYTE lpBytesBackup)
{
    LPVOID lpTrampoline;
    DWORD_PTR pdwPushRegsAddy;
    DWORD_PTR pdwHookCallAddy;
    DWORD_PTR pdwPopRegsAddy;
    DWORD_PTR pdwBytesBackupAddy;
    DWORD_PTR pdwBackjumpAddy;
    DWORD fdwDummy;
    lpTrampoline = VirtualAlloc(NULL, TRAMPOLINE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpTrampoline)
        return NULL;
    pdwPushRegsAddy = (DWORD_PTR)lpTrampoline;
    pdwHookCallAddy = pdwPushRegsAddy + 2;
    pdwPopRegsAddy = pdwHookCallAddy + 5;
    pdwBytesBackupAddy = pdwPopRegsAddy + 2;
    pdwBackjumpAddy = pdwBytesBackupAddy + HOOK_SIZE;
    *(BYTE *)pdwPushRegsAddy = _ASM_OP_PUSHAD;
    *(BYTE *)(pdwPushRegsAddy + 1) = _ASM_OP_PUSHFD;
    *(BYTE *)pdwHookCallAddy = _ASM_OP_CALL;

    // TODO
    *(DWORD *)(pdwHookCallAddy + 1) = ((DWORD_PTR)lpfnHook - pdwHookCallAddy - 5);

    *(BYTE *)pdwPopRegsAddy = _ASM_OP_POPFD;
    *(BYTE *)(pdwPopRegsAddy + 1) = _ASM_OP_POPAD;
    if (!memcpy((LPVOID)pdwBytesBackupAddy, lpBytesBackup, HOOK_SIZE))
    {
        VirtualFree(lpTrampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    *(BYTE *)pdwBackjumpAddy = _ASM_OP_JMP;
    // TODO
    *(DWORD *)(pdwBackjumpAddy + 1) = ((DWORD_PTR)lpfnTarget + HOOK_SIZE) - pdwBackjumpAddy - 5;

    if (!VirtualProtect(lpTrampoline, TRAMPOLINE_SIZE, PAGE_EXECUTE_READ, &fdwDummy) || !FlushInstructionCache(GetCurrentProcess(), lpTrampoline, TRAMPOLINE_SIZE))
    {
        VirtualFree(lpTrampoline, 0, MEM_RELEASE);
        return NULL;
    }
    return lpTrampoline;
}

bool hook_function(LPVOID lpTarget, LPVOID lpHook)
{
    DWORD fdwOldProtect;
    LPVOID lpTrampoline;
    BYTE aBytesBackup[HOOK_SIZE];
    if (!VirtualProtect(lpTarget, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &fdwOldProtect))
        return FALSE;
    if (!memcpy(aBytesBackup, lpTarget, HOOK_SIZE))
        return FALSE;
    lpTrampoline = CreateTrampoline(lpTarget, lpHook, aBytesBackup);
    if (!lpTrampoline)
        return FALSE;
    *(BYTE *)lpTarget = _ASM_OP_JMP;
    *(DWORD *)((DWORD_PTR)lpTarget + 1) = (DWORD_PTR)lpTrampoline - (DWORD_PTR)lpTarget - 5;
    *(BYTE *)((DWORD_PTR)lpTarget + 5) = _ASM_OP_NOP;
    VirtualProtect(lpTarget, HOOK_SIZE, fdwOldProtect, &fdwOldProtect);

    return true;
}

bool unhook_function(LPVOID lpTarget)
{
    DWORD fdwOldProtect;
    LPBYTE lpBytesBackup;
    LPVOID lpTrampoline;
    DWORD_PTR pOffset;
    if (!memcpy(&pOffset, (LPVOID)((DWORD_PTR)lpTarget + 1), 5))
        return FALSE;
    lpTrampoline = (LPVOID)((DWORD_PTR)lpTarget + pOffset + 5);
    lpBytesBackup = (LPBYTE)lpTrampoline + 9;
    if (!VirtualProtect(lpTarget, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &fdwOldProtect))
        return FALSE;
    if (!memcpy(lpTarget, lpBytesBackup, HOOK_SIZE))
        return FALSE;
    if (!VirtualProtect(lpTarget, HOOK_SIZE, fdwOldProtect, &fdwOldProtect))
        return FALSE;
    return VirtualFree(lpTrampoline, 0, MEM_RELEASE);
}
