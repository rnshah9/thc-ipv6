#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" unsigned char *thc_resolve6(char *target);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    
    std::string str = provider.ConsumeRandomLengthString();
    char* cstr = strdup(str.c_str());
    thc_resolve6(cstr);
    free(cstr);

    return 0;
}