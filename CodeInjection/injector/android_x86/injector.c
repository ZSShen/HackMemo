#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>


#define SUCC                    (0)
#define FAIL                    (1)
#define SIZE_BLAH_BUF           (1024)
#define SIZE_SHELLCODE          (256)
#define SIZE_PATHNAME           (512)

#define INTEL_RET_X86           (0xc3)
#define INTEL_INT3              (0xcc)
#define INTEL_NOOP              (0x90)


#define ERROR_MSG(msg)              do {                                        \
                                        printf("%s\n\t at %s line %d\n", msg,   \
                                               __FILE__, __LINE__);             \
                                    } while (0);

#define ERROR_MSG_BREAK(Label)      do {                                        \
                                        printf("Error: %s\n\tat %s line %d\n",  \
                                               strerror(errno), __FILE__,       \
                                               __LINE__);                       \
                                        rc = FAIL;                              \
                                        goto Label;                             \
                                    } while (0);

#define ERROR_RETURN(Label, ...)     do {                                       \
                                        rc = FAIL;                              \
                                        __VA_ARGS__;                            \
                                        goto Label;                             \
                                    } while (0);

typedef unsigned char uchar;
typedef unsigned long ulong;

void printUsage()
{
    printf("sudo ./injector TargetPID PathToLibrary\n");
}


/*----------------------------------------------------------------------------*
 *        The auxiliary functions to search for the memory footprints.        *
 *----------------------------------------------------------------------------*/
int getLibraryBgnAddr(pid_t pid, char *szLibKey, ulong *pAddrBgn)
{
    int rc = SUCC;

    char bufBlah[SIZE_BLAH_BUF];
    sprintf(bufBlah, "/proc/%d/maps", pid);
    FILE *fp = fopen(bufBlah, "r");
    if (!fp)
        ERROR_MSG_BREAK(RETURN);

    while (fgets(bufBlah, SIZE_BLAH_BUF, fp) != NULL) {
        if (!strstr(bufBlah, "r-xp"))
            continue;
        if (!strstr(bufBlah, szLibKey))
            continue;
        ulong addrEnd;
        sscanf(bufBlah, "%lx-%lx", pAddrBgn, &addrEnd);
        break;
    }

RETURN:
    return rc;
}

int getFunctionBgnAddr(char *szLib, char *szFunc, ulong *pAddrBgn)
{
    int rc = SUCC;

    void *hdLib = dlopen(szLib, RTLD_LAZY);
    if (!hdLib)
        ERROR_MSG_BREAK(RETURN);

    void *func = dlsym(hdLib, szFunc);
    if (!func)
        ERROR_MSG_BREAK(CLOSE);

    *pAddrBgn = (ulong)func;

CLOSE:
    dlclose(hdLib);
RETURN:
    return rc;
}

void getEpilogueRetAddr(ulong addrEpi, ulong *pAddrRet)
{
    uchar *pSlide = (uchar*)addrEpi;
    while (*pSlide != INTEL_RET_X86)
        --pSlide;
    *pAddrRet = (ulong)pSlide;
}


/*----------------------------------------------------------------------------*
 *         The auxiliary functions to manipulate the target process.          *
 *----------------------------------------------------------------------------*/
int ptraceAttach(pid_t pid)
{
    int rc = SUCC;

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
        ERROR_MSG_BREAK(RETURN);

    int status;
    if(waitpid(pid, &status, WUNTRACED) != pid)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceDetach(pid_t pid)
{
    int rc = SUCC;

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceGetRegs(pid_t pid, struct user_regs_struct *pRegs)
{
    int rc = SUCC;

    if (ptrace(PTRACE_GETREGS, pid, NULL, pRegs) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceSetRegs(pid_t pid, struct user_regs_struct *pRegs)
{
    int rc = SUCC;

    if (ptrace(PTRACE_SETREGS, pid, NULL, pRegs) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptracePeekText(pid_t pid, ulong addrText, void *pBuf, int countPeek)
{
    int rc = SUCC;

    long *pSlide = (long*)pBuf;
    int countRead = 0, idx = -1;
    while (countRead < countPeek) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, addrText + countRead, NULL);
        if (word == -1)
            ERROR_MSG_BREAK(RETURN);
        countRead += sizeof(word);
        pSlide[++idx] = word;
    }

RETURN:
    return rc;
}

int ptracePokeText(pid_t pid, ulong addrText, void *pBuf, int countPoke)
{
    int rc = SUCC;

    int countWrte = 0;
    while (countWrte < countPoke) {
        long word;
        memcpy(&word, pBuf + countWrte, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addrText + countWrte, word);
        if (word == -1)
            ERROR_MSG_BREAK(RETURN);
        countWrte += sizeof(word);
    }

RETURN:
    return rc;
}

int ptraceContinue(pid_t pid)
{
    int rc = SUCC;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceGetSignInfo(pid_t pid, siginfo_t *pSignInfo)
{
    int rc = SUCC;

    int status;
    if(waitpid(pid, &status, WUNTRACED) != pid)
        ERROR_MSG_BREAK(RETURN);

    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, pSignInfo) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}


/*----------------------------------------------------------------------------*
 *  The shellcode to load hooking library in the target process memory space. *
 *----------------------------------------------------------------------------*/
void shellcodeBgn()
{
    asm (
        /* ecx stores the to be allocated space size. */
        "push %ecx \n"
        /* eax stores the address of malloc(). */
        "call *%eax \n"
        /* The starting address of the allocated space is stored in eax. */
        "int $3"
    );

    asm (
        /* The second argument is set for RTLD_LAZY. */
        "push $1 \n"
        /* The first argument is set to the starting address of library pathname. */
        "push %esi \n"
        /* eax stores the address of dlopen(). */
        "call *%eax \n"
        "int $3"
    );

    asm (
        /* esi stores the starting address of the allocated space.*/
        "push %esi \n"
        /* eax stores the address of free(). */
        "call *%eax\n"
        "int $3"
    );
}

void shellcodeEnd()
{ /* Just a pivot to help us calculate the length of the compiled shellcode. */ }


int main(int argc, char **argv)
{
    if (argc != 3) {
        printUsage();
        return SUCC;
    }
    int rc = SUCC;

    /*----------------------------------------------------------------*
     *   Get the relevant function addresses of the target process.   *
     *----------------------------------------------------------------*/
    /* To resolve dlopen(). */
    pid_t pidMe = getpid();
    pid_t pidHim = atoi(argv[1]);

    ulong addrLinkerBgnMe;
    if (getLibraryBgnAddr(pidMe, "/system/bin/linker", &addrLinkerBgnMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrLinkderBgnHim;
    if (getLibraryBgnAddr(pidHim, "/system/bin/linker", &addrLinkderBgnHim) != SUCC)
        ERROR_RETURN(RETURN);

    ulong addrDlopenMe;
    if (getFunctionBgnAddr("libdl.so", "dlopen", &addrDlopenMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrDlopenHim = addrLinkderBgnHim + (addrDlopenMe - addrLinkerBgnMe);

    //printf("dlopen() Me : 0x%08x 0x%08x\n", addrLinkerBgnMe, addrDlopenMe);
    //printf("dlopen() Him: 0x%08x 0x%08x\n", addrLinkderBgnHim, addrDlopenHim);

    /* To resolve malloc(). */
    ulong addrLibcBgnMe;
    if (getLibraryBgnAddr(pidMe, "libc", &addrLibcBgnMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrLibcBgnHim;
    if (getLibraryBgnAddr(pidHim, "libc", &addrLibcBgnHim) != SUCC)
        ERROR_RETURN(RETURN);

    ulong addrMallocMe;
    if (getFunctionBgnAddr("libc.so", "malloc", &addrMallocMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrMallocHim = addrLibcBgnHim + (addrMallocMe - addrLibcBgnMe);
    //printf("malloc() Me : 0x%08lx 0x%08lx\n", addrLibcBgnMe, addrMallocMe);
    //printf("malloc() Him: 0x%08lx 0x%08lx\n", addrLibcBgnHim, addrMallocHim);

    /* To resolve free(). */
    ulong addrFreeMe;
    if (getFunctionBgnAddr("libc.so", "free", &addrFreeMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrFreeHim = addrLibcBgnHim + (addrFreeMe - addrLibcBgnMe);
    //printf("free() Me : 0x%08x 0x%08x\n", addrLibcBgnMe, addrFreeMe);
    //printf("free() Him: 0x%08x 0x%08x\n", addrLibcBgnHim, addrFreeHim);

    /*----------------------------------------------------------------*
     *             Prepare the to be injected objects.                *
     *----------------------------------------------------------------*/
    /* Prepare the shell code. */
    uchar codeShell[SIZE_SHELLCODE];
    int lenCode = (ulong)shellcodeEnd - (ulong)shellcodeBgn + 1;
    memcpy(codeShell, shellcodeBgn, lenCode);
    codeShell[lenCode - 1] = INTEL_INT3;

    div_t countWord = div(lenCode, sizeof(ulong));
    int iter, patch = (countWord.rem > 0)? (sizeof(ulong) - countWord.rem) : 0;
    for (iter = 0 ; iter < patch ; ++iter)
        codeShell[lenCode++] = INTEL_NOOP;

    /* Prepare the library pathname. */
    char szPath[SIZE_PATHNAME];
    int lenPath = strlen(argv[2]);
    strncpy(szPath, argv[2], lenPath);
    szPath[lenPath++] = 0;

    countWord = div(lenPath, sizeof(ulong));
    patch = (countWord.rem > 0)? (sizeof(ulong) - countWord.rem) : 0;
    for (iter = 0 ; iter < patch ; ++iter)
        szPath[lenPath++] = 0;

    /*----------------------------------------------------------------*
     *             Start to manipulate the target process.            *
     *----------------------------------------------------------------*/
    if (ptraceAttach(pidHim) != SUCC)
        ERROR_RETURN(RETURN);

    /* Backup the context  */
    struct user_regs_struct regOrig;
    if (ptraceGetRegs(pidHim, &regOrig) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    uchar codeOrig[SIZE_SHELLCODE];
    if (ptracePeekText(pidHim, regOrig.eip, codeOrig, lenCode) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    ulong addrInjectEntry = regOrig.eip;

    /* Force the target process to execute malloc() function. */
    struct user_regs_struct regModi;
    memcpy(&regModi, &regOrig, sizeof(struct user_regs_struct));
    regModi.eax = addrMallocHim;
    regModi.ecx = lenPath;

    if (ptraceSetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptracePokeText(pidHim, addrInjectEntry, codeShell, lenCode) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceContinue(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    siginfo_t signInfo;
    if (ptraceGetSignInfo(pidHim, &signInfo) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    if (signInfo.si_signo != SIGTRAP) {
        printf("Signal Number: %d\n", signInfo.si_signo);
        ERROR_MSG("The target process does not fire SIGTRAP but crash!");
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    }

    /* Force the target process to call dlopen(). */
    if (ptraceGetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    ulong addrLibPath = regModi.eax;

    if (ptracePokeText(pidHim, addrLibPath, szPath, lenPath) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    printf("PathName:%lx, %d\n", addrLibPath, lenPath);

    regModi.eax = addrDlopenHim;
    regModi.esi = addrLibPath;
    if (ptraceSetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceContinue(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceGetSignInfo(pidHim, &signInfo) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    if (signInfo.si_signo != SIGTRAP) {
        ERROR_MSG("The target process does not fire SIGTRAP but crash!");
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    }

    /* Force the target process to execute free() function. */
    if (ptraceGetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    regModi.eax = addrFreeHim;
    regModi.esi = addrLibPath;

    if (ptraceSetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceContinue(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceGetSignInfo(pidHim, &signInfo) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    if (signInfo.si_signo != SIGTRAP) {
        printf("Signal Number: %d\n", signInfo.si_signo);
        ERROR_MSG("The target process does not fire SIGTRAP but crash!");
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    }

    /* At this stage, we finish the task and should restore the context of the
       target process. */
    if (ptracePokeText(pidHim, addrInjectEntry, codeOrig, lenCode) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    if (ptraceSetRegs(pidHim, &regOrig) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    ptraceDetach(pidHim);

RETURN:
    return rc;
}
