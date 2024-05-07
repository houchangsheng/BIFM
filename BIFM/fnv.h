#ifndef UTIL_H
#define UTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "config.h"

uint64          fnv64Bit(unsigned char pBuffer[], int start, int end);
unsigned int*   fnv256Bit(unsigned char pBuffer[], int start, int end);
void            mulWithPrime2(uint256 hash_val, uint256 result);

#endif  /* UTIL_H */

