#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
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
#define SIZE_TINY_BLAH          (64)
#define SIZE_MID_BLAH           (512)
#define SIZE_LONG_BLAH          (1024)
#define SIZE_SEGMENT            (4096)

#define OPT_LONG_ZYGOTE         "zygote"
#define OPT_LONG_APPNAME        "app"
#define OPT_LONG_LIBPATH        "lib"
#define OPT_ZYGOTE              'z'
#define OPT_APPNAME             'a'
#define OPT_LIBPATH             'l'

#define PATH_LINKER             "/system/bin/linker"
#define PATH_LIBC               "/system/lib/libc.so"
#define NAME_LINKER             "libdl.so"
#define FUNC_MMAP               "mmap"
#define FUNC_DLOPEN             "dlopen"


#define CUSMSG(msg)                 do {                                        \
                                        printf("%s\n\pidWait at %s line %d\n", msg,   \
                                               __FILE__, __LINE__);             \
                                    } while (0);

#define BRK_SYSMSG(Label)           do {                                        \
                                        printf("Error: %s\n\tat %s line %d\n",  \
                                               strerror(errno), __FILE__,       \
                                               __LINE__);                       \
                                        rc = FAIL;                              \
                                        goto Label;                             \
                                    } while (0);

#define BRK_ACTION(Label, ...)      do {                                        \
                                        rc = FAIL;                              \
                                        __VA_ARGS__;                            \
                                        goto Label;                             \
                                    } while (0);

typedef unsigned char uchar;
typedef unsigned long ulong;


void printUsage()
{
    const char *cszMsg = "Usage: ./injector --zygote PID --app APPNAME --lib LIBPATH\n"
    "                  -z       PID -a    APPNAME -l    LIBPATH\n\n"
    "Example: ./injector --zygote 933 --app org.zsshen.bmi --lib /data/local/tmp/libhook.so\n"
    "         ./injector -z       933 -a    org.zsshen.bmi -l    /data/local/tmp/libhook.so\n\n";
    printf("%s", cszMsg);
}


/*----------------------------------------------------------------------------*
 *  The auxiliary functions to search for the process or memory footprints.   *
 *----------------------------------------------------------------------------*/
int getLibraryBgnAddr(pid_t pid, char *szLibKey, ulong *pAddrBgn)
{
    int rc = SUCC;

    char bufBlah[SIZE_MID_BLAH];
    sprintf(bufBlah, "/proc/%d/maps", pid);
    FILE *fp = fopen(bufBlah, "r");
    if (!fp)
        BRK_SYSMSG(EXIT);

    while (fgets(bufBlah, SIZE_MID_BLAH, fp) != NULL) {
        if (!strstr(bufBlah, "r-xp"))
            continue;
        if (!strstr(bufBlah, szLibKey))
            continue;
        ulong addrEnd;
        sscanf(bufBlah, "%lx-%lx", pAddrBgn, &addrEnd);
        break;
    }

EXIT:
    return rc;
}

int getFunctionBgnAddr(char *szLib, char *szFunc, ulong *pAddrBgn)
{
    int rc = SUCC;

    void *hdLib = dlopen(szLib, RTLD_LAZY);
    if (!hdLib)
        BRK_SYSMSG(EXIT);

    void *func = dlsym(hdLib, szFunc);
    if (!func)
        BRK_SYSMSG(CLOSE);

    *pAddrBgn = (ulong)func;

CLOSE:
    dlclose(hdLib);
EXIT:
    return rc;
}


/*----------------------------------------------------------------------------*
 *         The auxiliary functions to manipulate the target process.          *
 *----------------------------------------------------------------------------*/
int ptraceAttach(pid_t pid)
{
    int rc = SUCC;
    errno = 0;

    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
        BRK_SYSMSG(EXIT);

    int status;
    if(waitpid(pid, &status, WUNTRACED) != pid)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceDetach(pid_t pid)
{
    int rc = SUCC;
    errno = 0;

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceGetRegs(pid_t pid, struct user_regs_struct *pRegs)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_GETREGS, pid, NULL, pRegs) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceSetRegs(pid_t pid, struct user_regs_struct *pRegs)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, pRegs) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptracePeekText(pid_t pid, ulong addrText, void *pBuf, int countPeek)
{
    int rc = SUCC;
    errno = 0;

    long *pSlide = (long*)pBuf;
    int countRead = 0, idx = -1;
    while (countRead < countPeek) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, addrText + countRead, NULL);
        if (word == -1)
            BRK_SYSMSG(EXIT);
        countRead += sizeof(word);
        pSlide[++idx] = word;
    }

EXIT:
    return rc;
}

int ptracePokeText(pid_t pid, ulong addrText, void *pBuf, int countPoke)
{
    int rc = SUCC;
    errno = 0;

    int countWrte = 0;
    while (countWrte < countPoke) {
        long word;
        memcpy(&word, pBuf + countWrte, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addrText + countWrte, word);
        if (word == -1)
            BRK_SYSMSG(EXIT);
        countWrte += sizeof(word);
    }

EXIT:
    return rc;
}

int ptraceContinue(pid_t pid)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceWait(pid_t pid, int* pStatus)
{
    int rc = SUCC;
    errno = 0;

    if (pid == -1)
        waitpid(pid, pStatus, __WALL);
    else {
        if (waitpid(pid, pStatus, WUNTRACED) != pid)
            BRK_SYSMSG(EXIT);
    }

EXIT:
    return rc;
}

int ptraceGetSignInfo(pid_t pid, siginfo_t *pSignInfo)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, pSignInfo) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceGetEventMsg(pid_t pidParent, void* pMsg)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_GETEVENTMSG, pidParent, NULL, pMsg) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceSysCall(pid_t pid)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}

int ptraceSetOption(pid_t pid, long opt)
{
    int rc = SUCC;
    errno = 0;

    if (ptrace(PTRACE_SETOPTIONS, pid, 1, opt) == -1)
        BRK_SYSMSG(EXIT);

EXIT:
    return rc;
}


/*----------------------------------------------------------------------------*
 *            The primary logic to inject library into target app.            *
 *----------------------------------------------------------------------------*/
int captureTargetApp(pid_t pidZygote, char *szApp, pid_t *pPidApp)
{
    int rc = SUCC;

    /* Attach to the zygote process and wait for the target app to be forked. */
    if (ptraceAttach(pidZygote) != SUCC)
        BRK_ACTION(EXIT);

    if (ptraceSetOption(pidZygote, PTRACE_O_TRACEFORK) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidZygote));

    if (ptraceContinue(pidZygote) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidZygote));

    char bufBlah[SIZE_MID_BLAH];
    int status;
    pid_t pidApp = 0, pidWait = pidZygote;
    while (true) {
        pidWait = waitpid(pidWait, &status, __WALL);

        if (pidWait != 0 && pidWait == pidApp) {
            /* Read the process startup command to check for target app. */
            sprintf(bufBlah, "/proc/%d/cmdline", pidApp);
            int fd = open(bufBlah, O_RDONLY);
            if (fd < 0)
                continue;
            read(fd, bufBlah, sizeof(char) * SIZE_MID_BLAH);
            close(fd);

            if (strstr(bufBlah, szApp)) {
                /* Now we catch the target app. */
                printf("[+] Catch the target app %d -> %s\n", pidApp, bufBlah);
                *pPidApp = pidApp;
                break;
            }
            else {
                /* Force the app stop at next system call entry. */
                if (ptraceSysCall(pidApp) != SUCC)
                    BRK_ACTION(EXIT, ptraceDetach(pidZygote) &&
                                     ptraceDetach(pidApp));
                continue;
            }
        }

        if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
            /* Get the newly forked app PID. */
            if (ptraceGetEventMsg(pidWait, &pidApp) != SUCC)
                BRK_ACTION(EXIT, ptraceDetach(pidZygote));
            printf("[+] Parent PID: %d\n[+] Child  PID: %d\n", pidWait, pidApp);

            /* Let the parent process continue its work. */
            if (ptraceContinue(pidWait) != SUCC)
                BRK_ACTION(EXIT, ptraceDetach(pidZygote) &&
                                 ptraceDetach(pidApp));
            pidWait = pidApp;
        }
    }

    /* Release the zygote.
       Idealy, we should detach it here. But it seems to go away at this point,
       thus the return value of ptrace is -1. */
    //ptraceDetach(pidZygote);

EXIT:
    return rc;
}

int resolveFunctionAddress(pid_t pidApp, ulong *pAddrDlopen, ulong *pAddrMmap)
{
    int rc = SUCC;
    pid_t pidMe = getpid();

    ulong addrLinkerBgnMe;
    if (getLibraryBgnAddr(pidMe, PATH_LINKER, &addrLinkerBgnMe) != SUCC)
        BRK_ACTION(EXIT);
    ulong addrLinkderBgn;
    if (getLibraryBgnAddr(pidApp, PATH_LINKER, &addrLinkderBgn) != SUCC)
        BRK_ACTION(EXIT);

    ulong addrLibcBgnMe;
    if (getLibraryBgnAddr(pidMe, PATH_LIBC, &addrLibcBgnMe) != SUCC)
        BRK_ACTION(EXIT);
    ulong addrLibcBgn;
    if (getLibraryBgnAddr(pidApp, PATH_LIBC, &addrLibcBgn) != SUCC)
        BRK_ACTION(EXIT);

    ulong addrDlopenMe;
    if (getFunctionBgnAddr(NAME_LINKER, FUNC_DLOPEN, &addrDlopenMe) != SUCC)
        BRK_ACTION(EXIT);
    *pAddrDlopen = addrLinkderBgn + (addrDlopenMe - addrLinkerBgnMe);

    ulong addrMmapMe;
    if (getFunctionBgnAddr(PATH_LIBC, FUNC_MMAP, &addrMmapMe) != SUCC)
        BRK_ACTION(EXIT);
    *pAddrMmap = addrLibcBgn + ((ulong)mmap - addrLibcBgnMe);

EXIT:
    return rc;
}

int injectTargetApp(pid_t pidApp, char *szLib, ulong addrDlopen, ulong addrMmap)
{
    int rc = SUCC;

    /* Prepare the library pathname. */
    char szPath[SIZE_MID_BLAH];
    int lenPath = strlen(szLib);
    strncpy(szPath, szLib, lenPath);
    szPath[lenPath++] = 0;

    div_t countWord = div(lenPath, sizeof(ulong));
    int iter, patch = (countWord.rem > 0)? (sizeof(ulong) - countWord.rem) : 0;
    for (iter = 0 ; iter < patch ; ++iter)
        szPath[lenPath++] = 0;

    /* Backup the context. */
    struct user_regs_struct regOrig;
    if (ptraceGetRegs(pidApp, &regOrig) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    /* Force the target process to execute mmap().
       To fit the calling convention,
       arrParam[0] stores the return address, and
       arrParam[6] to arrParam[1] is the actual parameters of mmap(). */
    ulong arrParam[SIZE_TINY_BLAH];
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
    regModi.eip = addrMmap;
    regModi.esp -= byteRepl;

    if (ptracePokeText(pidApp, regModi.esp, arrParam, byteRepl) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    if (ptraceSetRegs(pidApp, &regModi) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    if (ptraceContinue(pidApp) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    /* The injector will receive a SIGSEGV triggered by invalid return address. */
    int status;
    if (ptraceWait(pidApp, &status) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    /* Retrieve the address of the newly mapped memory segment. */
    if (ptraceGetRegs(pidApp, &regModi) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));
    ulong addrMap = regModi.eax;
    printf("[+] mmap() successes with %lx returned\n", addrMap);

    if (ptracePokeText(pidApp, addrMap, szPath, lenPath) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    /* Force the target process to call dlopen().
       To fit the calling convention,
       arrParam[0] stores the return address, and
       arrParam[2] to arrParam[1] is the actual parameters of dlopen(). */
    arrParam[0] = 0;
    arrParam[1] = addrMap;
    arrParam[2] = RTLD_LAZY;
    byteRepl = sizeof(long) * 3;
    regModi.eip = addrDlopen;
    regModi.esp -= byteRepl;

    if (ptracePokeText(pidApp, regModi.esp, arrParam, byteRepl) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    if (ptraceSetRegs(pidApp, &regModi) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    if (ptraceContinue(pidApp) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    /* The injector will receive a SIGSEGV triggered by invalid return address. */
    if (ptraceWait(pidApp, &status) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));
    printf("[+] dlopen() successes \n");

    /* At this stage, we finish the task and should restore the context of the
       target process. */
    if (ptraceSetRegs(pidApp, &regOrig) != SUCC)
        BRK_ACTION(EXIT, ptraceDetach(pidApp));

    ptraceDetach(pidApp);

EXIT:
    return rc;
}


int main(int argc, char **argv)
{
    int rc = SUCC;

    /* Acquire the command line arguments. */
    static struct option Options[] = {
        {OPT_LONG_APPNAME, required_argument, 0, OPT_APPNAME},
        {OPT_LONG_LIBPATH, required_argument, 0, OPT_LIBPATH},
    };

    char szOrder[SIZE_TINY_BLAH];
    memset(szOrder, 0, sizeof(char) * SIZE_TINY_BLAH);
    sprintf(szOrder, "%c:%c:%c:", OPT_ZYGOTE, OPT_APPNAME, OPT_LIBPATH);

    int opt, idxOpt;
    pid_t pidZygote = 0;
    char *szApp = NULL, *szLib = NULL;
    while ((opt = getopt_long(argc, argv, szOrder, Options, &idxOpt)) != -1) {
        switch (opt) {
            case OPT_ZYGOTE:
                pidZygote = atoi(optarg);
                break;
            case OPT_APPNAME:
                szApp = optarg;
                break;
            case OPT_LIBPATH:
                szLib = optarg;
                break;
            default:
                BRK_ACTION(EXIT, printUsage());
        }
    }

    if (pidZygote == 0 || !szApp || !szLib)
        BRK_ACTION(EXIT, printUsage());

    pid_t pidApp;
    rc = captureTargetApp(pidZygote, szApp, &pidApp);
    if (rc != SUCC)
        goto EXIT;

    ulong addrDlopen, addrMmap;
    rc = resolveFunctionAddress(pidApp, &addrDlopen, &addrMmap);
    if (rc != SUCC)
        goto EXIT;

    injectTargetApp(pidApp, szLib, addrDlopen, addrMmap);

EXIT:
    return rc;
}
