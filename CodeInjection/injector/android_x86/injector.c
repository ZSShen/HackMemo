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
#include <sys/mman.h>


#define SUCC                    (0)
#define FAIL                    (1)
#define SIZE_BLAH_BUF           (1024)
#define SIZE_PATHNAME           (512)
#define SIZE_SEGMENT            (4096)
#define COUNT_PARAM             (16)

#define INTEL_RET_X86           (0xc3)
#define INTEL_INT3              (0xcc)
#define INTEL_NOOP              (0x90)

#define PATH_LINKER             "/system/bin/linker"
#define PATH_LIBC               "/system/lib/libc.so"
#define NAME_LINKER             "libdl.so"
#define FUNC_MMAP               "mmap"
#define FUNC_DLOPEN             "dlopen"


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

int ptraceWait(pid_t pid)
{
    int rc = SUCC, status;

    if (waitpid(pid, &status, WUNTRACED) != pid)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceGetSignInfo(pid_t pid, siginfo_t *pSignInfo)
{
    int rc = SUCC;

    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, pSignInfo) == -1)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}

int ptraceWaitSysCall(pid_t pid)
{
    int rc = SUCC;

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
        ERROR_MSG_BREAK(RETURN);

    int status;
    if (waitpid(pid, &status, WUNTRACED) != pid)
        ERROR_MSG_BREAK(RETURN);

RETURN:
    return rc;
}


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
    if (getLibraryBgnAddr(pidMe, PATH_LINKER, &addrLinkerBgnMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrLinkderBgnHim;
    if (getLibraryBgnAddr(pidHim, PATH_LINKER, &addrLinkderBgnHim) != SUCC)
        ERROR_RETURN(RETURN);

    ulong addrLibcBgnMe;
    if (getLibraryBgnAddr(pidMe, PATH_LIBC, &addrLibcBgnMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrLibcBgnHim;
    if (getLibraryBgnAddr(pidHim, PATH_LIBC, &addrLibcBgnHim) != SUCC)
        ERROR_RETURN(RETURN);

    ulong addrDlopenMe;
    if (getFunctionBgnAddr(NAME_LINKER, FUNC_DLOPEN, &addrDlopenMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrDlopenHim = addrLinkderBgnHim + (addrDlopenMe - addrLinkerBgnMe);

    ulong addrMmapMe;
    if (getFunctionBgnAddr(PATH_LIBC, FUNC_MMAP, &addrMmapMe) != SUCC)
        ERROR_RETURN(RETURN);
    ulong addrMmapHim = addrLibcBgnHim + ((ulong)mmap - addrLibcBgnMe);
    //printf("mmap() Me : 0x%08lx 0x%08lx\n", addrLibcBgnMe, addrMmapMe);
    //printf("mmap() Him: 0x%08lx 0x%08lx\n", addrLibcBgnHim, addrMmapHim);

    /*----------------------------------------------------------------*
     *             Start to manipulate the target process.            *
     *----------------------------------------------------------------*/
    /* Prepare the library pathname. */
    char szPath[SIZE_PATHNAME];
    int lenPath = strlen(argv[2]);
    strncpy(szPath, argv[2], lenPath);
    szPath[lenPath++] = 0;

    div_t countWord = div(lenPath, sizeof(ulong));
    int iter, patch = (countWord.rem > 0)? (sizeof(ulong) - countWord.rem) : 0;
    for (iter = 0 ; iter < patch ; ++iter)
        szPath[lenPath++] = 0;

    printf("[+] Start to injector the target %d.\n", pidHim);
    if (ptraceAttach(pidHim) != SUCC)
        ERROR_RETURN(RETURN);

    /* Backup the context. */
    struct user_regs_struct regOrig;
    if (ptraceGetRegs(pidHim, &regOrig) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    /* Force the target process to execute mmap().
       To fit the calling convention,
       arrParam[0] stores the return address, and
       arrParam[6] to arrParam[1] is the actual parameters of mmap(). */
    ulong arrParam[COUNT_PARAM];
    arrParam[0] = 0;
    arrParam[1] = 0;
    arrParam[2] = SIZE_SEGMENT;
    arrParam[3] = PROT_READ | PROT_WRITE | PROT_EXEC;
    arrParam[4] = MAP_ANONYMOUS | MAP_PRIVATE;
    arrParam[5] = 0;
    arrParam[6] = 0;
    int byteRepl = sizeof(ulong) * 7;

    struct user_regs_struct regModi;
    memcpy(&regModi, &regOrig, sizeof(struct user_regs_struct));
    regModi.eip = addrMmapHim;
    regModi.esp -= byteRepl;

    if (ptracePokeText(pidHim, regModi.esp, arrParam, byteRepl) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceSetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceContinue(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    /* The injector will receive a SIGSEGV triggered by invalid return address. */
    if (ptraceWait(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    /* Retrieve the address of the newly mapped memory segment. */
    if (ptraceGetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    ulong addrMap = regModi.eax;
    printf("[+] mmap() successes!\n");

    if (ptracePokeText(pidHim, addrMap, szPath, lenPath) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    /* Force the target process to call dlopen().
       To fit the calling convention,
       arrParam[0] stores the return address, and
       arrParam[2] to arrParam[1] is the actual parameters of dlopen(). */
    arrParam[0] = 0;
    arrParam[1] = addrMap;
    arrParam[2] = RTLD_LAZY;
    byteRepl = sizeof(long) * 3;
    regModi.eip = addrDlopenHim;
    regModi.esp -= byteRepl;

    if (ptracePokeText(pidHim, regModi.esp, arrParam, byteRepl) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceSetRegs(pidHim, &regModi) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    if (ptraceContinue(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    /* The injector will receive a SIGSEGV triggered by invalid return address. */
    if (ptraceWait(pidHim) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));
    printf("[+] dlopen() successes!\n");

    /* At this stage, we finish the task and should restore the context of the
       target process. */
    if (ptraceSetRegs(pidHim, &regOrig) != SUCC)
        ERROR_RETURN(RETURN, ptraceDetach(pidHim));

    ptraceDetach(pidHim);

RETURN:
    return rc;
}
