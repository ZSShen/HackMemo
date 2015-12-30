#ifndef _STRINGPRINTF_H_
#define _STRINGPRINTF_H_


#include <string>

#include <stdlib.h>
#include <stdarg.h>


// Auxiliary buffer size.
static constexpr int kBlahSize 		= 1024;
static constexpr int kBlahSizeTiny 	= 128;

// Returns a string corresponding to printf-like formatting of the arguments.
std::string StringPrintf(const char* fmt, ...)
        __attribute__((__format__(__printf__, 1, 2)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendF(std::string* dst, const char* fmt, ...)
        __attribute__((__format__(__printf__, 2, 3)));

// Appends a printf-like formatting of the arguments to 'dst'.
void StringAppendV(std::string* dst, const char* format, va_list ap);

#endif