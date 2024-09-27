#include <stdio.h>
#include <time.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"
#include "nw.h"
#include "funcs.h"
#include "../Enclave/dh/tools.h"
#include "../Enclave/dh/tweetnacl.h"

double
timespec_to_ns(struct timespec tp)
{
    return ((double)tp.tv_sec / 1.0e-9) + (double)tp.tv_nsec;
}


double
get_time_diff(struct timespec a, struct timespec b)
{
    return (double)(timespec_to_ns(a) - timespec_to_ns(b));
}

void                                            
print_key(const char *s, uint8_t *key, size_t size) 
{    
    size_t i;
    printf("%s: ", s);                          
    for (i = 0; i < size; i++)                  
        printf("%u", key[i]);                   
    printf("\n");                               
}                                               
