#ifndef HASHING_H
#define	HASHING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "fnv.h"
#include "bloomfilter.h"

#include "BitmapTable.h"

uint32_t         SuperFastHash(const void *buf, size_t len);
uint32           roll_hashx(unsigned char c, uchar window[], uint32 rhData[]);
BitmapTable**    hashBufferToBF(char* flow_ID, BLOOMFILTER** bf, BitmapTable** bitmap_table, int& flow_num, unsigned char* byte_buffer, unsigned int bytes_read);
unsigned int*    checkBufferInBF(char* flow_ID, BLOOMFILTER** bf, int threshold_b, int threshold, BitmapTable** bitmap_table, int flow_num, unsigned char* byte_buffer, unsigned int bytes_read);
void             hexDump(char* desc, void* addr, int len);

#endif	/* HASHING_H */

