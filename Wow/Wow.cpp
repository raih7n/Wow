#include "common.h"

#include <wil/resource.h>

// x64 code all bytes beginning with 0x4? are prefixes
// but in x86 code, all bytes beginning with 0x4? are valid instructions
void memCpy64(void* dst, DWORD64 src, size_t size)
{
    if (!dst || src == 0 || size == 0)
        return;

    // In order to have the inline assembler not break that stack, two DWORDS are needed
    // using DWORD64 will generate the wrong pop word ptr[]
    union reg64 {
        DWORD64 v;
        DWORD dw[2];
    };

    reg64 rsrc = { src };

    // http://ref.x86asm.net/coder32.html#x40 http://ref.x86asm.net/coder64.html#x40
    // for context, the inc & dec instructions (40+r & 48+r) are placed with REX prefixes in x64
    __asm
    {
        X64_Start();

        push edi;
        push esi;


    }

}


int main()
{
    NTSTATUS status = STATUS_SUCCESS;

    spdlog::info("Wow! started");

    SYSTEM_INFO	info{};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        spdlog::error("This program cannot run on native x86");
        return 0;
    }

 


    return 0;
}

