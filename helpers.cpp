#include <Windows.h>
#include <Psapi.h>

#include <string>

// This return the address of PS_SYSTEM_DLL_INIT_BLOCK.CfgBitMap
// https://github.com/processhacker/processhacker/blob/4187c48f24cbf0ad0a0a955c53775b2bd0e49a16/phnt/include/ntldr.h#L618
PVOID GetCfgBitmapPointer()
{
    PVOID pCfgBitmap = NULL;

    // PS_SYSTEM_DLL_INIT_BLOCK is exported from ntdll as LdrSystemDllInitBlock, but the structure itself is not documented
    // and the offset has changed previously.
    // We could hardcode offsets, or bruteforce this block looking for a pointer that matches the expected 2TB MEM_MAPPED
    // region characteristics.
    // However, the first instruction of LdrControlFlowGuardEnforced is usually -
    //   48 83 xx xx xx xx 00 00  cmp PS_SYSTEM_DLL_INIT_BLOCK.CfgBitMap, 0
    // So we can calculate the absolute address from the rel32 offset in this instruction.
    PVOID pLdrControlFlowGuardEnforced = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrControlFlowGuardEnforced");
    if (!pLdrControlFlowGuardEnforced)
        return NULL;

    PUCHAR Rip = (PUCHAR)pLdrControlFlowGuardEnforced + 8;
    PDWORD pRipRelativeOffset = (PDWORD)((PUCHAR)pLdrControlFlowGuardEnforced + 3);
    DWORD RipRelativeOffset = 0;
    SIZE_T szBytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), pRipRelativeOffset, &RipRelativeOffset, sizeof(RipRelativeOffset), &szBytesRead))
        return NULL;

    return Rip + RipRelativeOffset;
}

PULONG_PTR GetCfgBitmap(HANDLE hProcess)
{
    static PVOID ppCfgBitmap = GetCfgBitmapPointer();
    PULONG_PTR pCfgBitmap = NULL;
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T szBytesRead = 0;
    if (!ppCfgBitmap ||
        !ReadProcessMemory(hProcess, ppCfgBitmap, &pCfgBitmap, sizeof(pCfgBitmap), &szBytesRead) ||
        (0 == pCfgBitmap) ||
        !VirtualQueryEx(hProcess, pCfgBitmap, &mbi, sizeof(mbi)))
    {
        return NULL;
    }

    // Quick sanity check that our CFG bitmap pointer is the base of a MEM_MAPPED allocation.
    // We could also validate that it is 2TB in size.
    if ((mbi.AllocationBase != pCfgBitmap) || (MEM_MAPPED != mbi.Type))
    {
        printf("%p PS_SYSTEM_DLL_INIT_BLOCK.CfgBitMap = %p is invalid\n", ppCfgBitmap, pCfgBitmap);
        pCfgBitmap = NULL;
    }

    return pCfgBitmap;
}

const char *TypeString(MEMORY_BASIC_INFORMATION* pMbi)
{
    switch (pMbi->Type)
    {
    case MEM_PRIVATE:
        return "MEM_PRIVATE";
    case MEM_MAPPED:
        return "MEM_MAPPED";
    case MEM_IMAGE:
        return "MEM_IMAGE";
    }

    if (pMbi->State == MEM_FREE)
        return "MEM_FREE";

    return "<ERROR>";
};

const char *ProtectionString(DWORD protection, DWORD state)
{
    if (state == MEM_RESERVE)
        return "MEM_RESERVE";

    switch (protection)
    {
    case PAGE_EXECUTE:
        return "--X";
    case PAGE_EXECUTE_READ:
        return "R-X";
    case PAGE_EXECUTE_WRITECOPY:
        return "RCX";
    case PAGE_EXECUTE_READWRITE:
        return "RWX";
    case PAGE_READWRITE:
        return "RW-";
    case PAGE_READONLY:
        return "R--";
    case PAGE_WRITECOPY:
        return "RC-";
    case PAGE_NOACCESS:
        return "---";
    }

    return "<ERROR>";
};