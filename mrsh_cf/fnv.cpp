#include "fnv.h"
#include <stdio.h>
#include <string.h>

uint64 fnv64Bit(unsigned char pBuffer[], int start, int end)
{
    uint64 nHashVal = 0xcbf29ce484222325ULL,
        nMagicPrime = 0x00000100000001b3ULL;

    int i = start;
    while (i <= end)
    {
        nHashVal ^= pBuffer[i++];
        nHashVal *= nMagicPrime;
    }
    return nHashVal;
}