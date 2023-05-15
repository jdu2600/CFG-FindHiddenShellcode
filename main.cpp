#include <stdio.h>
#include <Windows.h>

#include <Psapi.h>
#include <tlhelp32.h>
#include <assert.h>

#include <string>
#include <vector>

PULONG_PTR GetCfgBitmap(HANDLE hProcess);
const char* TypeString(MEMORY_BASIC_INFORMATION* pMbi);
const char* ProtectionString(DWORD protection, DWORD state);

SYSTEM_INFO g_sysinfo{};

constexpr auto PAGE_EXECUTE_FLAGS = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
constexpr unsigned int CFG_INDEX_SHIFT = 9;

std::vector<PVOID> GetProcessPreviouslyExecutableRegions(HANDLE hProcess, bool bAggressive=false)
{
    std::vector<PVOID> result;

    MEMORY_BASIC_INFORMATION mbi{};
    MEMORY_BASIC_INFORMATION mbiCfg{};
    PULONG_PTR pCfgBitMap = GetCfgBitmap(hProcess);
    ULONG_PTR va;

    if (!pCfgBitMap)
        goto cleanup;
    
    // We walk the VA address space via the CFG Bitmap to find all contiguous private executable regions.
    // For each of these, we compare against the current region state to determine if the region has been hidden.

    va = 0;
    while (va < (ULONG_PTR)g_sysinfo.lpMaximumApplicationAddress)
    {
        PULONG_PTR pCfgEntry = pCfgBitMap + ((ULONG_PTR)va >> CFG_INDEX_SHIFT);
        if (!VirtualQueryEx(hProcess, (PVOID)pCfgEntry, &mbiCfg, sizeof(mbiCfg)))
            break; // process stopped

        if (MEM_COMMIT == mbiCfg.State)
        {
            // Found some committed CFG page(s) - but are they private and exectuable?
            SIZE_T hiddenRegionSize = 0;
            ULONG_PTR hiddenRegionStart = 0;
            ULONG_PTR vaRegionEnd = va + mbiCfg.RegionSize * 64;
            while (va < vaRegionEnd)
            {
                pCfgEntry = pCfgBitMap + ((ULONG_PTR)va >> CFG_INDEX_SHIFT);
                SIZE_T stBytesRead = 0;
                ULONG_PTR ulEntry = 0;
                // TODO(jdu) This per-entry read is inefficient - just read the whole region upfront instead.
                if (!ReadProcessMemory(hProcess, pCfgEntry, &ulEntry, sizeof(ulEntry), &stBytesRead))
                    break;

                // We're only interested in non-executable pages that contain (all) CFG call targets
                if (MAXULONG_PTR == ulEntry)
                {
                    if (0 == hiddenRegionSize)
                    {
                        hiddenRegionStart = va;
                    }
                    hiddenRegionSize += g_sysinfo.dwPageSize;
                }

                va += g_sysinfo.dwPageSize;

                if ((hiddenRegionSize > 0) && ((MAXULONG_PTR != ulEntry) || (va == vaRegionEnd)))
                {
                    // The CFG bitmap indicates that this region has been executable during the lifetime
                    // of the process. Now check the VAD tree.

                    MEMORY_BASIC_INFORMATION mbiStart{};
                    MEMORY_BASIC_INFORMATION mbiEnd{};
                    if (VirtualQueryEx(hProcess, (PVOID)hiddenRegionStart, &mbiStart, sizeof(mbi)) &&
                        (MEM_COMMIT == mbiStart.State) &&
                        VirtualQueryEx(hProcess, (PVOID)(hiddenRegionStart + hiddenRegionSize - 1), &mbiEnd, sizeof(mbi)))
                    {
                        // Is this region non-executable in the VAD tree?
                        bool bHiddenRegion = !(PAGE_EXECUTE_FLAGS & mbiStart.Protect) &&
                            !(PAGE_EXECUTE_FLAGS & mbiStart.AllocationProtect);

                        // Handle a few common (likely) false positives.
                        bool bLikelyFalsePositive = 
                            (mbiStart.AllocationBase != mbiEnd.AllocationBase) || // hidden region overlaps allocation
                            (hiddenRegionSize == 0x3000);                         // 12K region
                        
                        if (bHiddenRegion && (bAggressive || !bLikelyFalsePositive))
                        {
                            result.push_back((PVOID)(hiddenRegionStart));
                        }
                    }

                    hiddenRegionStart = 0;
                    hiddenRegionSize = 0;
                }
            }
        }
        va += mbiCfg.RegionSize * 64; // Each CFG BitMap page corresponds to 64 VA pages
    }

cleanup:
    return result;
}


// Outputs the details of discovered hidden regions.
// If you scanned aggressively, then this includes commentary about FP potential.
void DumpHiddenExecutableAllocations(HANDLE hProcess, const std::vector<PVOID>& hiddenExecutableAllocations)
{
    MEMORY_BASIC_INFORMATION mbi{};
    MEMORY_BASIC_INFORMATION mbiCfg{};
    PULONG_PTR pCfgBitMap = (PULONG_PTR)GetCfgBitmap(hProcess);

    for (const auto& allocation : hiddenExecutableAllocations)
    {
        if (!VirtualQueryEx(hProcess, allocation, &mbi, sizeof(mbi)))
            break;

        printf(" * %p %s\n", allocation, TypeString(&mbi));

        DWORD allocationHiddenPages = 0;
        SIZE_T allocationSize = 0;
        for (ULONG_PTR i = (ULONG_PTR)allocation; mbi.AllocationBase == allocation; i += mbi.RegionSize)
        {
            if (!VirtualQueryEx(hProcess, (PVOID)i, &mbi, sizeof(mbi)))
                break;

            DWORD regionHiddenPages = 0;
            bool HiddenRegionOverlaps = false;

            if (mbi.AllocationBase == allocation && !(PAGE_EXECUTE_FLAGS & mbi.Protect))
            {
                for (ULONG_PTR j = (ULONG_PTR)mbi.BaseAddress; j < ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize); j += (64 * g_sysinfo.dwPageSize))
                {
                    PULONG_PTR pEntry = pCfgBitMap + ((ULONG_PTR)j >> CFG_INDEX_SHIFT);

                    if (!VirtualQueryEx(hProcess, pEntry, &mbiCfg, sizeof(mbiCfg)) || (MEM_COMMIT != mbiCfg.State) ||
                        (MEM_MAPPED != mbiCfg.Type) || (PAGE_NOACCESS == mbiCfg.Protect))
                        continue; // Skip if no CFG BitMap page

                    // Check the first entry for every VA page on this CFG BitMap page for previous executable protection
                    int cfgPageEnd = 64 - (((ULONG_PTR)j / g_sysinfo.dwPageSize) % 64); // determine where on the CFG page our VA resides
                    for (int k = 0; (k < cfgPageEnd) && (j + k * g_sysinfo.dwPageSize) < ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize); k++)
                    {
                        PULONG_PTR pEntry = pCfgBitMap + (((ULONG_PTR)j + k * g_sysinfo.dwPageSize) >> CFG_INDEX_SHIFT);
                        SIZE_T stBytesRead = 0;
                        ULONG_PTR ulEntry = 0;
                        if (!ReadProcessMemory(hProcess, pEntry, &ulEntry, sizeof(ulEntry), &stBytesRead))
                            break;

                        // We're only interested in non-executable pages that contain (all) CFG call targets
                        regionHiddenPages += (MAXULONG_PTR == ulEntry);
                    }
                }
            }
            else if ((mbi.AllocationBase != allocation))
            {
                // two cases... ends with MEM_RESERVE, or ends with MEM_FREE?
                bool IsLastPageHidden = false;
                bool IsNextPageHidden = false;
                {

                    PULONG_PTR pEntry = pCfgBitMap + ((i - g_sysinfo.dwPageSize) >> CFG_INDEX_SHIFT);
                    SIZE_T stBytesRead = 0;
                    ULONG_PTR ulEntry = 0;
                    if (!ReadProcessMemory(hProcess, pEntry, &ulEntry, sizeof(ulEntry), &stBytesRead))
                        break;

                    IsLastPageHidden = (MAXULONG_PTR == ulEntry);
                }

                {
                    PULONG_PTR pEntry = pCfgBitMap + (i >> CFG_INDEX_SHIFT);
                    SIZE_T stBytesRead = 0;
                    ULONG_PTR ulEntry = 0;
                    if (!ReadProcessMemory(hProcess, pEntry, &ulEntry, sizeof(ulEntry), &stBytesRead))
                        break;

                    IsNextPageHidden = (MAXULONG_PTR == ulEntry);
                }
                HiddenRegionOverlaps = IsLastPageHidden && IsNextPageHidden;
            }

            if ((0 != mbi.AllocationProtect) && (mbi.AllocationBase == allocation))
            {
                allocationHiddenPages += regionHiddenPages;
                allocationSize += mbi.RegionSize;
                if (0 != regionHiddenPages)
                    printf("   - %p +0x%06zx %s %s %d/%zu hidden pages\n", mbi.BaseAddress, mbi.RegionSize, ProtectionString(mbi.AllocationProtect, 0), ProtectionString(mbi.Protect, mbi.State), regionHiddenPages, mbi.RegionSize / g_sysinfo.dwPageSize);
            }
            else if (HiddenRegionOverlaps)
            {
                printf("   --> likely FP. Hidden region overlaps boundary.\n");
            }
            else if ((allocationSize != allocationHiddenPages * g_sysinfo.dwPageSize) && (mbi.AllocationBase != allocation) && (0 != regionHiddenPages))
            {
                printf("   --> likely FP. allocation<->CFG mismatch. Previously executable dimensions overlap allocation.\n");
                break;
            }

        }
        if ((allocationSize == allocationHiddenPages * g_sysinfo.dwPageSize))
        {
            PULONG_PTR pEntry = pCfgBitMap + (((ULONG_PTR)mbi.AllocationBase + allocationSize) >> CFG_INDEX_SHIFT);
            if (!VirtualQueryEx(hProcess, pEntry, &mbiCfg, sizeof(mbiCfg)) || (MEM_COMMIT != mbiCfg.State) ||
                (MEM_MAPPED != mbiCfg.Type) || (PAGE_NOACCESS == mbiCfg.Protect))
            {
                continue; // Skip if no CFG BitMap page
            }
            SIZE_T stBytesRead = 0;
            ULONG_PTR ulEntry = 0;
            if (!ReadProcessMemory(hProcess, pEntry, &ulEntry, sizeof(ulEntry), &stBytesRead))
                break;

            if (MAXULONG_PTR == ulEntry)
            {
                printf("   --> likely FP. allocation<->CFG mismatch. Previously executable dimensions overlap allocation.\n");
            }
        }
    }
}

int main(int argc, char* argv[])
{
    bool bAggressive = false; // skip some likely false positives

    std::vector<PVOID> hiddenAllocations;
    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32{};

    GetSystemInfo(&g_sysinfo);

    printf("===== Hidden Executable Pages - %s scanning all processes =====\n", bAggressive ? "aggressively " : "quickly");

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    assert(hProcessSnap != INVALID_HANDLE_VALUE);

    pe32.dwSize = sizeof(PROCESSENTRY32);
    (void)Process32First(hProcessSnap, &pe32);
    assert(NULL != pe32.szExeFile);

    do
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (NULL == hProcess)
            continue;  // access is denied, skip

        hiddenAllocations = GetProcessPreviouslyExecutableRegions(hProcess, bAggressive);
        if (hiddenAllocations.size() > 0)
        {
            printf("%ls(%d) - %zu hidden allocations\n", pe32.szExeFile, pe32.th32ProcessID, hiddenAllocations.size());
            DumpHiddenExecutableAllocations(hProcess, hiddenAllocations);
        }

        CloseHandle(hProcess);
    } while (Process32Next(hProcessSnap, &pe32));

    return 0;
}

