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

    reg64 reg_src = { src };

    // http://ref.x86asm.net/coder32.html#x40 http://ref.x86asm.net/coder64.html#x40
    // for context, the inc & dec instructions (40+r & 48+r) are placed with REX prefixes in x64
    // I also have the option to paste memcpy.asm from the CRT source, but that is overengineering
    __asm
    {
        X64_Start();

        push edi;
        push esi;

        mov edi, dst;
        ;// REX_W is needed here because we're dealing with a 64bit src
        ;// this instruction equates to mov rsi, qword ptr [reg_src]
        REX_W mov esi, reg_src.dw[0];
        mov ecx, size;

        ;// Optimized divisionm 4 byte chunks each
        ;// x >> 2 = x / 4
        ;// doing this is faster than division operations, but the real technqiue would be to use xmm regs
        mov eax, ecx;
        and eax, 3;
        shr ecx, 2;

        rep movsd;

        test eax, eax;
        je __mov0;
        cmp eax, 1;
        je __mov1;

        movsw;
        cmp eax, 2;
        je __mov0;

    __mov1:
        movsb;

    __mov0:
        pop esi;
        pop edi;

        X64_End();
    }

}

bool memCmp64(void* dst, DWORD64 src, size_t size)
{
    if (!dst || src == 0 || size == 0)
        return false;

    bool res = false;

    // In order to have the inline assembler not break that stack, two DWORDS are needed
    // using DWORD64 will generate the wrong pop word ptr[]
    union reg64 {
        DWORD64 v;
        DWORD dw[2];
    };

    reg64 reg_src = { src };

    // http://ref.x86asm.net/coder32.html#x40 http://ref.x86asm.net/coder64.html#x40
    // for context, the inc & dec instructions (40+r & 48+r) are placed with REX prefixes in x64
    // I also have the option to paste memcpy.asm from the CRT source, but that is overengineering
    __asm
    {
        X64_Start();

        push edi;
        push esi;

        mov edi, dst;
        ;// REX_W is needed here because we're dealing with a 64bit src
        ;// this instruction equates to mov rsi, qword ptr [reg_src]
        REX_W mov esi, reg_src.dw[0];
        mov ecx, size;

        ;// Optimized divisionm 4 byte chunks each
        ;// x >> 2 = x / 4
        ;// doing this is faster than division operations, but the real technique would be to use xmm regs
        mov eax, ecx;
        and eax, 3;
        shr ecx, 2;

        repe cmpsd;
        jnz __ret_not_equal;

        test eax, eax;
        je __set_equal;
        cmp eax, 1;
        je __compare1;

        cmpsw;
        jnz __ret_not_equal;
        cmp eax, 2;
        je __set_equal;

    __compare1:
        cmpsd;
        jnz __ret_not_equal;

    __set_equal:
        mov res, 1;

    __ret_not_equal:
        pop esi;
        pop edi;

        X64_End()
    }

    return res;
}

DWORD64 x64call(DWORD64 pfn, int argC, ...)
{
    /*
     * according to msdn at https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160
     * By default, the x64 calling convention passes the first four arguments to a function in registers.
     * The registers used for these arguments depend on the position and type of the argument.
     * Remaining arguments get pushed on the stack in right-to-left order.
     * Integer valued arguments in the leftmost four positions are passed in left-to-right order in RCX, RDX, R8, and R9, respectively.
     * The fifth and higher arguments are passed on the stack as previously described.
     * All integer arguments in registers are right-justified, so the callee can ignore the upper bits of the register and access only the portion of the register necessary. 
     */
    va_list args;
    va_start(args, argC);

    union reg64 {
        DWORD64 v;
        DWORD dw[2];
    };
    reg64 reg_rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    reg64 reg_rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    reg64 reg_r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    reg64 reg_r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    reg64 reg_rax = { 0 };

    reg64 stackArgs = { (DWORD64)&va_arg(args, DWORD64) };

    // easier now to cast it to a QWORD than in the inline assembler
    reg64 reg_argC = { (DWORD64)argC };

    WORD old_fs = 0;
    DWORD old_esp = 0;

    __asm
    {
        ;// reset fs 
        ;//https://eyalitkin.wordpress.com/2017/08/18/bypassing-return-flow-guard-rfg/
        mov old_fs, fs;
        mov eax, 0x2B;
        mov fs, ax;

        ;// save original esp
        mov old_esp, esp;

        X64_Start();

        ;// move the first four arguments into their appropriate registers
        ;// mov rcx, qword ptr [reg_rcx]
        REX_W mov ecx, reg_rcx.dw[0];
        // mov rdx, qword ptr [reg_rdx]
        REX_W mov edx, reg_rdx.dw[0];
        push reg_r8.v;
        ;// pop r8
        X64_Pop(0x8);
        push reg_r9.v;
        ;// pop r9
        X64_Pop(0x9);

        ;// mov rdx, qword ptr [argC]
        REX_W mov eax, reg_argC.dw[0];

        ;// adjust the stack for the rest of the arguments
        test al, 1;
        jnz __dont_adjust;
        sub esp, 8;
        

    __dont_adjust:
        push edi;
        ;// mov rdi, qword ptr [stackArgs]
        REX_W mov edi, stackArgs.dw[0];

        ;// move the rest of the arguments to the stack
        ;// test rax, rax
        REX_W test eax, eax;
        
    __mov0:
        ;// test rax, rax
        REX_W test eax, eax;
        jz __call0;
        push dword ptr[edi];
        ;// sub rdi, 8
        REX_W sub edi, 8;
        ;// sub rax, 1
        REX_W sub eax, 1;
        jmp _mov0;

    __call0:
        ;// sub rsp, 0x20
        REX_W sub esp, 0x20;

        call pfn;

        ;// clean the stack
        ;// mov rdx, qword ptr [argC]
        REX_W mov ecx, mov_argC.dw[0];
        ;// lea rsp, qword ptr[rsp + 8 * rdx + 0x20]
        REX_W lea esp, dword ptr[esp + 8 * ecx + 0x20];

        pop edi;

        ;// mov qword ptr [rax], rax
        REX_W mov reg_rax.dw[0], eax;

        X64_End();

        mov as, ds;
        mov ss, ax;
        mov esp, old_esp;
        mov ax, old_fs;
        mov fs, ax;
    }
    return reg_rax.v;
}

DWORD64 GetProceAddress64(DWORD64 module, std::string funcname)
{
    if (!module)
        return 0;

    IMAGE_DOS_HEADER doshdr;
    memCpy64(&doshdr, module, sizeof(doshdr));

    if (doshdr.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS64 nthdr;
    memCpy64(&nthdr, module + doshdr.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

    IMAGE_DATA_DIRECTORY& idexports = nthdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!idexports.VirtualAddress)
        return 0;

    IMAGE_EXPORT_DIRECTORY exportData;
    memCpy64(&idexports, module + idexports.VirtualAddress, sizeof(idexports));

    auto rvaTable = std::make_unique<DWORD>(sizeof(DWORD) * exportData.NumberOfFunctions);
    memCpy64(rvaTable.get(), module + exportData.AddressOfFunctions, sizeof(DWORD) * exportData.NumberOfFunctions);

    auto ordinTable = std::make_unique<WORD>(sizeof(WORD) * exportData.NumberOfFunctions);
    memCpy64(ordinTable.get(), module + exportData.AddressOfNameOrdinals, sizeof(WORD) * exportData.NumberOfFunctions);

    auto nameTable = std::make_unique<DWORD>(sizeof(DWORD) * exportData.NumberOfNames);
    memCpy64(nameTable.get(), module + exportData.AddressOfNames, sizeof(DWORD) * exportData.NumberOfNames);

    for (int i = 0; i < exportData.NumberOfFunctions; ++i)
    {
        if (!memCmp64((void*)funcname.c_str(), module + nameTable.get()[i], funcname.length()))
            continue;
        else
            return module + rvaTable.get()[ordinTable.get()[i]];
    }

    return 0;
}

DWORD64 GetModuleHandle64(std::wstring modulename)
{
    union reg64 {
        DWORD64 v;
        DWORD dw[2];
    };
    // get the x64 teb, should always be in r12
    reg64 r12;
    r12.v = 0;

    X64_Start();
    X64_Push(0xC);
    __asm pop r12.dw[0];
    X64_End();

    TEB teb64;
    memCpy64(&teb64, r12.v, sizeof(TEB));

    PEB peb64;
    memCpy64(&peb64, (DWORD64)teb64.ProcessEnvironmentBlock, sizeof(PEB));

    PEB_LDR_DATA ldr;
    memCpy64(&ldr, (DWORD64)peb64.Ldr, sizeof(PEB_LDR_DATA));

    DWORD64 lastEntry = (DWORD64)peb64.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList);
    LDR_DATA_TABLE_ENTRY head;
    head.InLoadOrderLinks.Flink = ldr.InInitializationOrderModuleList.Flink;
    do
    {
        memCpy64(&head, (DWORD64)head.InMemoryOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY));

        auto wstr = std::make_unique<wchar_t>(head.BaseDllName.MaximumLength);
        memCpy64(wstr.get(), (DWORD64)head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

        std::wstring mwstr(wstr.get());
        if (!modulename.compare(mwstr))
            return (DWORD64)head.DllBase;

    } while ((DWORD64)head.InLoadOrderLinks.Flink != lastEntry);

    return 0;
}

int main()
{
    spdlog::info("Wow! started");

    SYSTEM_INFO	info{};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        spdlog::error("This program cannot run on native x86");
        return 0;
    }
    
    auto ntdll64 = GetModuleHandle64(L"ntdll.dll");
    
    spdlog::info("Found x64 ntdll.dll @ 0x{:X}", ntdll64);

    static auto pfnVirtualAllocEx64 = GetProceAddress64(ntdll64, "VirtualAllocEx");

    DWORD64 x64pool = 0;
    DWORD64 x64poolsize = 0x1000;

    auto status = x64call(pfnVirtualAllocEx64, 4, (DWORD64)GetCurrentProcess(),
        (DWORD64)&x64pool, (DWORD64)&x64poolsize, 
        (DWORD64)(MEM_COMMIT | MEM_RESERVE), (DWORD64)PAGE_READWRITE);

    if (!NT_SUCCESS(status))
    {
        spdlog::info("x64 VirtualAllocEx failed with status 0x{:X}", status);
        return 0;
    }

    spdlog::info("VirtualAlloc succeeded, allocated 0x1000 bytes @ 0x{:X}", x64pool);

    return 0;
}

