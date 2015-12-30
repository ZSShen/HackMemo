
#include "stringprintf.h"
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>


int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << StringPrintf("Usage: [Target PID] [Beginning Segment Offset]\n");
        return EXIT_FAILURE;
    }

    pid_t pid = atoi(argv[1]);
    char* addr_bgn_tge = argv[2];

    // Determine the beginning and ending offsets of the segment.
    char buf[kBlahSize];
    off_t addr_bgn, addr_end;
    sprintf(buf, "/proc/%d/maps", pid);
    std::ifstream map(buf, std::ifstream::in);
    while (map.good() && !map.eof()) {
        map.getline(buf, kBlahSize);
        if (!strstr(buf, addr_bgn_tge))
            continue;
        sscanf(buf, "%x-%x", &addr_bgn, &addr_end);
        break;
    }

    // Attach to the target process.
    int32_t status;
    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    waitpid(pid, &status, WUNTRACED);

    // Peek the segment data.
    off_t ofst = 0;
    off_t cur_addr = addr_bgn;
    size_t size_word = sizeof(int);
    while (ofst < (addr_end - addr_bgn)) {
        int word_1 = ptrace(PTRACE_PEEKDATA, pid, addr_bgn + ofst, nullptr);
        ofst += size_word;

        int word_2 = ptrace(PTRACE_PEEKDATA, pid, addr_bgn + ofst, nullptr);
        ofst += size_word;

        int word_3 = ptrace(PTRACE_PEEKDATA, pid, addr_bgn + ofst, nullptr);
        ofst += size_word;

        int word_4 = ptrace(PTRACE_PEEKDATA, pid, addr_bgn + ofst, nullptr);
        ofst += size_word;

        std::cout << StringPrintf("0x%08x: %02x %02x %02x %02x %02x %02x %02x %02x"
                                  "  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                  cur_addr,
                                  (word_1 & 0xff), ((word_1 >> 8) & 0xff),
                                  ((word_1 >> 16) & 0xff), ((word_1 >> 24) & 0xff),
                                  (word_2 & 0xff), ((word_2 >> 8) & 0xff),
                                  ((word_2 >> 16) & 0xff), ((word_2 >> 24) & 0xff),
                                  (word_3 & 0xff), ((word_3 >> 8) & 0xff),
                                  ((word_3 >> 16) & 0xff), ((word_3 >> 24) & 0xff),
                                  (word_4 & 0xff), ((word_4 >> 8) & 0xff),
                                  ((word_4 >> 16) & 0xff), ((word_4 >> 24) & 0xff));
        cur_addr += size_word << 2;
    }

    // Detach from the target process.
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    return EXIT_SUCCESS;
}