##How to compile the code
```
nasm -felf64 YourProgram.asm -o YourProgram.o
ld -s YourProgram.o -o YourProgram
```