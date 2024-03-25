// This file contains the function pointers to the ntapi/win32 api functions that are to be dynamically resolved at runtime

#include <API/headers/api.h>
#include <utils/headers/tools.h>
#include <utils/headers/CRTdefs.h>
#include <string>
#include <sstream>
#include <cstdint>
#include <unordered_map>
#include <functional>
#include "utils/headers/antianalysis.h"

#define SEED 5

using namespace API;

template <typename T, T Value>
struct integral_constant {
    static constexpr T value = Value;
};

API::APIResolver API::APIResolver::instance;

// Generate seed for string hashing
consteval int API::RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto g_KEY = API::RandomCompileTimeSeed() % 0xFF; // Create seed variable

// compile time Djb2 hashing function (ASCII)
constexpr DWORD API::HashStringDjb2A(const char* string) {
    ULONG hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *string++)) {
        hash = ((hash << SEED) + hash) + c;
    }

    return hash;
}

// compile time Djb2 hashing function (Unicode)
constexpr DWORD API::HashStringDjb2W(const wchar_t* string) {
    ULONG hash = (ULONG)g_KEY;
    wchar_t c = 0;
    while ((c = *string++)) {
        hash = ((hash << SEED) + hash) + c;
    }
    return hash;
}


namespace hashes
{
    /* MODULE HASHES*/
    constexpr DWORD ntdll    = integral_constant<DWORD, HashStringDjb2A("ntdll.dll")>::value;
    constexpr DWORD kernel32 = integral_constant<DWORD, HashStringDjb2A("kernel32.dll")>::value;



    /* NTDLL */
    constexpr DWORD NtQueryInformationProcess  = integral_constant<DWORD, HashStringDjb2A("NtQueryInformationProcess")>::value;
    constexpr DWORD NtCreateProcess            = integral_constant<DWORD, HashStringDjb2A("NtCreateProcess")>::value;
    constexpr DWORD NtTerminateProcess         = integral_constant<DWORD, HashStringDjb2A("NtTerminateProcess")>::value;
    constexpr DWORD NtCreateThread             = integral_constant<DWORD, HashStringDjb2A("NtCreateThread")>::value;
    constexpr DWORD LdrLoadDll                 = integral_constant<DWORD, HashStringDjb2A("LdrLoadDll")>::value;
    constexpr DWORD NtOpenProcess              = integral_constant<DWORD, HashStringDjb2A("NtOpenProcess")>::value;
    constexpr DWORD NtCreateFile               = integral_constant<DWORD, HashStringDjb2A("NtCreateFile")>::value;
    constexpr DWORD RtlInitUnicodeString       = integral_constant<DWORD, HashStringDjb2A("RtlInitUnicodeString")>::value;

    /* KERNEL32 */
    constexpr DWORD SetFileInformationByHandle = integral_constant<DWORD, HashStringDjb2A("SetFileInformationByHandle")>::value;
    constexpr DWORD GetCurrentProcess          = integral_constant<DWORD, HashStringDjb2A("GetCurrentProcess")>::value;


};

//APIResolver::APIResolver()
//{
//    this->IATCamo();
//    this->LoadModules();
//    this->ResolveFunctions();
//}

APIResolver::~APIResolver()
{
    FreeModules();
}

const API_ACCESS& APIResolver::GetAPIAccess() const
{
    return api;
}


// This function will resolve all of the functions in our API_FUNCTIONS struct
void APIResolver::ResolveFunctions()
{
    //Logging tools;


    //   // Map function names to function pointers
    //std::unordered_map<std::string, std::function<void* ()>> functionMap = 
    //{
    //    {hashes::NtQueryInformationProcess, []() { return GetProcessAddressByHash(api.mod.Ntdll, hashes::NtQueryInformationProcess); }},
    //    {hashes::NtCreateProcess, []() { return GetProcessAddressByHash(api.mod.Ntdll, hashes::NtCreateProcess); }},
    //    {hashes::NtCreateThread, []() { return GetProcessAddressByHash(api.mod.Ntdll, hashes::NtCreateThread); }},
    //    {hashes::LdrLoadDll, []() { return GetProcessAddressByHash(this->api.mod.Ntdll, hashes::LdrLoadDll); }},
    //};

    api.func.pNtQueryInformationProcess  = reinterpret_cast<pNtQueryInformationProcess_t> (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtQueryInformationProcess));
    api.func.pNtCreateProcess            = reinterpret_cast<pNtCreateProcess_t>           (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateProcess));
    api.func.pNtCreateThread             = reinterpret_cast<pNtCreateThread_t>            (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateThread));
    api.func.pLdrLoadDll                 = reinterpret_cast<pLdrLoadDll_t>                (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::LdrLoadDll));
    api.func.pNtOpenProcess              = reinterpret_cast<pNtOpenProcess_t>             (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtOpenProcess));
    api.func.pNtCreateFile               = reinterpret_cast<pNtCreateFile_t>              (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateFile));
    api.func.RtlInitUnicodeString        = reinterpret_cast<RtlInitUnicodeString_t>       (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::RtlInitUnicodeString));

    api.func.pSetFileInformationByHandle = reinterpret_cast<pSetFileInformationByHandle_t>(GetProcessAddressByHash(this->api.mod.Kernel32, hashes::SetFileInformationByHandle));


}

PVOID API::APIResolver::_(PVOID* ppAddress)
{
    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!pAddress)
        return NULL;

    // set the first 4 byte in pAddress to a random number
    *(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

    *ppAddress = pAddress;

    return pAddress;
}


void APIResolver::LoadModules()
{
    //Logging tools;

   /* this->api.mod.Kernel32 = LoadLibraryA("kernel32.dll");
    this->api.mod.Ntdll    = LoadLibraryA("ntdll.dll");*/

    this->api.mod.Kernel32 = GetModuleHandleByHash(hashes::kernel32);
    this->api.mod.Ntdll    = GetModuleHandleByHash(hashes::ntdll);

    if (!this->api.mod.Kernel32)
        //tools.ShowError("Failed to get handle to kernel32");
        return;
    if (!this->api.mod.Ntdll)
        return;
    //tools.ShowError("Failed to get handle to Ntdll");
}

void API::APIResolver::IATCamo()
{
    PVOID		pAddress = NULL;
    int* dummy = (int*)_(&pAddress);

    // This if statement will never run
    if (*dummy > 350) {

        // Whitelisted Winapis
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }
    HeapFree(GetProcessHeap(), 0, pAddress);
}

void APIResolver::FreeModules()
{

    if (this->api.mod.Kernel32)
        FreeLibrary(api.mod.Kernel32);
    if (this->api.mod.Ntdll)
        FreeLibrary(api.mod.Ntdll);
}

uintptr_t API::GetProcessAddressByHash(void* pBase, DWORD func)
{
    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);

    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva  = NULL;

    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);

    // Check magic number 
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        //tools.ShowError("Program Invalid: Incorrect DOS signature");
        return NULL;
    }

    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers

    // Get File and Optional headers
    pFileHeader = &pNtHeaders->FileHeader;
    pOptHeader  = &pNtHeaders->OptionalHeader;


    // Verify that there is enough space for the NT headers
    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pOptHeader->SizeOfImage)
    {
        //tools.ShowError("Program Invalid: Insufficient space for NT headers");
        return NULL;
    }

    // Verify that the optional header contains enough data directories
    if (pOptHeader->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
    {
        // tools.ShowError("Program Invalid: Insufficient data directories");
        return NULL;
    }

    // Get the size and virtual address of the export directory
    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exports_rva  = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Verify that the export directory is within the image boundaries
    if (exports_rva + exports_size > pOptHeader->SizeOfImage)
    {
        //tools.ShowError("Program Invalid: Export directory out of bounds");
        return NULL;
    }

    pExportDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
    DWORD* pEAT  = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 


    // Iterate through the functions in the export directory and check for a match
    for (unsigned int i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfNames)[i]);

        if (HashStringDjb2A(szNames) == func)
        {
            unsigned short usOrdinal = reinterpret_cast<unsigned short*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
            uintptr_t address        = reinterpret_cast<uintptr_t>      (pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfFunctions)[usOrdinal]);

            // Check if the function is forwarded
            if (address >= reinterpret_cast<uintptr_t>(pExportDir) && address < reinterpret_cast<uintptr_t>(pExportDir) + exports_size)
            {
                char cForwarderName[MAX_PATH] = { 0 };
                char* pcFunctionMod           = nullptr;
                char* pcFunctionName          = nullptr;
                DWORD dwDotOffset             = 0x0;

                memcpy(cForwarderName, reinterpret_cast<void*>(address), strlen(reinterpret_cast<char*>(address)));

                for (int j = 0; j < strlen(cForwarderName); j++)
                {
                    if (cForwarderName[j] == '.')
                    {
                        dwDotOffset = j;
                        cForwarderName[j] = NULL;
                        break;
                    }
                }

                pcFunctionMod  = cForwarderName;
                pcFunctionName = cForwarderName + dwDotOffset + 1;

                return GetProcessAddressByHash(LoadLibraryA(pcFunctionMod), HashStringDjb2A(pcFunctionName)); // TODO: use pLdrLoadDll
            }
            return address;
        }
    }

    return NULL;
}


HMODULE API::GetModuleHandleByHash(UINT32 hash)
{
    AntiAnalysis peb;

    auto &resolver = API::APIResolver::GetInstance();


   //PPEB pPeb                   = peb.GetPeb(API::APIResolver::GetInstance()).PebBaseAddress;
   //PPEB_LDR_DATA pLdr          = (PPEB_LDR_DATA)(pPeb->Ldr);
   //PLDR_DATA_TABLE_ENTRY  pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    auto penis1                  = peb.GetPeb(resolver);
    auto penis = penis1.PebBaseAddress;
    
    PPEB pPeb = penis;
    PPEB_LDR_DATA pLdr         = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);


    // Return the handle of the local .exe image
    if (!hash)
        return (HMODULE)pDte->Reserved2[0];

    while (pDte) {

        if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

            CHAR    cLDllName[MAX_PATH] = { 0 };
            DWORD   x = 0x00;

            while (pDte->FullDllName.Buffer[x]) {
                CHAR	wC = pDte->FullDllName.Buffer[x];
                // Convert to lowercase
                if (wC >= 'A' && wC <= 'Z')
                    cLDllName[x] = wC - 'A' + 'a';
                // Copy other characters (numbers, special characters ...)
                else
                    cLDllName[x] = wC;

                x++;
            }

            cLDllName[x] = '\0';

            if (HashStringDjb2W(pDte->FullDllName.Buffer) == hash || HashStringDjb2A(cLDllName) == hash)
                return (HMODULE)pDte->Reserved2[0];
        }

        // Move to the next node in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}