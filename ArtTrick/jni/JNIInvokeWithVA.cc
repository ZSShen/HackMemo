#include <iostream>
#include <vector>
#include <cstdarg>
#include <ffi.h>


bool CheckArguemnt(int amount, ...)
{
    va_list arg;
    va_start(arg, amount);
    for (int i = 0 ; i < amount ; ++i) {
        int value = va_arg(arg, int);
        std::cout << value << std::endl;
    }
    std::cout << std::endl;
    va_end(arg);

    return false;
}

int main()
{
    int count = 10;
    int array[count + 1];
    for (int i = 1 ; i <= count ; ++i)
        array[i] = i;
    bool flag[2];
    flag[0] = false; flag[1] = true;

    ffi_cif cif;
    ffi_type* arg_types[count + 1];
    void* arg_values[count + 1];
    arg_types[0] = &ffi_type_uint32;
    arg_values[0] = &count;

    int flip_flop = 0;
    for (int i = 1 ; i <= count ; ++i) {
        if ((i >> 1 << 1) != i) {
            arg_types[i] = &ffi_type_uint32;
            arg_values[i] = &(array[i]);
        } else {
            arg_types[i] = &ffi_type_uint8;
            arg_values[i] = &(flag[flip_flop]);
            flip_flop = (flip_flop == 0)? 1 : 0;
        }
    }

    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, count + 1, &ffi_type_uint8, arg_types) == FFI_OK) {
        void (*fptr)() = reinterpret_cast<void(*)()>(CheckArguemnt);
        bool rc;
        ffi_call(&cif, fptr, &rc, arg_values);
        std::cout << rc << std::endl;
    }

    return 0;
}
