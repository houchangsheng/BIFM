#ifndef BLOOMFILTER_H
#define	BLOOMFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "config.h"
#include "fnv.h"

// For a filter_size of FILTERSIZE Bytes (in the net-version probably 512 MB oder 1024 MB).
typedef struct
{
    //unsigned char bytes_array[BF_SIZE_IN_BYTES];
    //unsigned char* bytes_array = new unsigned char[BF_SIZE_IN_BYTES];
    unsigned char* bytes_array;
}BLOOMFILTER;

void            initialize_settings();

BLOOMFILTER*    init_empty_BF();
void            destroy_bf(BLOOMFILTER* bf);

void            add_hash_to_bloomfilter(BLOOMFILTER* bf, uint256 hash_val);
void            unset_bit(BLOOMFILTER* bf, unsigned int bit);
short           is_in_bloom(BLOOMFILTER* bf, uint256 hash_val);

void            print_bf(BLOOMFILTER* bf);
void            readFileToBF(const char* filename, BLOOMFILTER* bf);

#endif	/* BLOOM_H */
