#ifndef HASHING_H
#define	HASHING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "fnv.h"
#include "bloomfilter.h"

uint32           roll_hashx(unsigned char c, uchar window[], uint32 rhData[]);
unsigned int*    hashFileAndDo(BLOOMFILTER* bf, unsigned char* byte_buffer, int doWhat, unsigned int start, unsigned int stop);
unsigned int*    hashFileAndDo(char* flow_ID, BLOOMFILTER* bf, unsigned char* byte_buffer, int doWhat, unsigned int start, unsigned int stop);
double           entropy(unsigned int freqArray[], int size);
int              createResultsSummary(BLOOMFILTER* bf, uint256 hash_val, unsigned int* results_summary);
int              createResultsSummary(BLOOMFILTER* bf, uint256 hash_val, uint256 hash_val_flow_ID, unsigned int* results_summary);

void             hexDump(char* desc, void* addr, int len);

#endif	/* HASHING_H */

