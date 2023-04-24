#include <stdio.h>
#include <windows.h>
#include <winternl.h>

BOOL DetectHook(LPVOID hookedfuncaddr) {
    BYTE realbytes[] = "\x4C\x8B\xD1\xB8";
    if (memcmp(realbytes, hookedfuncaddr, 4) == 0) {
        return true;
    }
    else {
        return false;
    }
}

void Banner() {
    printf(R"EOF(

    _   ___ ___   _  _          _   _             ___      _          _           
   /_\ | _ \_ _| | || |___  ___| |_(_)_ _  __ _  |   \ ___| |_ ___ __| |_ ___ _ _ 
  / _ \|  _/| |  | __ / _ \/ _ \ / / | ' \/ _` | | |) / -_)  _/ -_) _|  _/ _ \ '_|
 /_/ \_\_| |___| |_||_\___/\___/_\_\_|_||_\__, | |___/\___|\__\___\__|\__\___/_|  
                                          |___/                        
                                  
                                    [Coded by MrEmpy]

)EOF");
}

void Help(char* progname) {
    printf(R"EOF(usage: %s OUTPUT
    options:
      OUTPUT,                   output file
)EOF", progname);
}

int main(int argc, char* argv[]) {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == NULL) {
        printf("[-] Error loading ntdll.dll\n");
        return 1;
    }

    if (argv[1] == NULL) {
        Banner();
        Help(argv[0]);
        return 1;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)dos_header + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)ntdll + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* function_addresses = (DWORD*)((char*)ntdll + exports->AddressOfFunctions);
    WORD* function_ordinals = (WORD*)((char*)ntdll + exports->AddressOfNameOrdinals);
    DWORD* function_names = (DWORD*)((char*)ntdll + exports->AddressOfNames);

    int outputfname = strlen(argv[1]) + 1;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[1], outputfname, NULL, 0);
    wchar_t* wdmpout = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, argv[1], outputfname, wdmpout, wlen);
    HANDLE outputf = CreateFileW(wdmpout, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    char breakline[] = "\n";

    Banner();
    puts("[*] NT API being hooked:");
    puts("=========================================================================================");
    for (int i = 0; i < exports->NumberOfFunctions; i++) {
        //printf("%s\n", (char*)ntdll + function_names[i]);
        if (strncmp((char*)ntdll + function_names[i], "Nt", 2) == 0) {
            FARPROC procaddr = GetProcAddress(ntdll, (LPCSTR)(char*)ntdll + function_names[i]);
            if (procaddr == NULL) {
                printf("[-] Error finding function %s\n", (char*)ntdll + function_names[i]);
                return 1;
            }
            LPBYTE lpprocaddr = (LPBYTE)procaddr;
            DWORD dwprocaddr = *(DWORD*)lpprocaddr;

            char realbytes[] = "0xB8D18B4C";
            DWORD Written;
            if (DetectHook(procaddr) == false) {
                printf("[-] %s [%s != 0x%02X]\n", (char*)ntdll + function_names[i], realbytes, dwprocaddr);
                WriteFile(outputf, (char*)ntdll + function_names[i], strlen((char*)ntdll + function_names[i]), &Written, NULL);
                WriteFile(outputf, breakline, strlen(breakline), &Written, NULL);
            }
        }
    }
    puts("=========================================================================================");

    CloseHandle(outputf);
    FreeLibrary(ntdll);
    return 0;
}
