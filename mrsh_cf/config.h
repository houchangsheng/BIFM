#ifndef CONFIG_H
#define	CONFIG_H

#define ROLLING_WINDOW          7
//#define BLOCK_SIZE              320// 256
//#define BLOCK_SIZE              64 //origin 320// 256
#define SHIFTOPS                11
#define MASK                    0x7FF
#define FILTERSIZE              256
#define SUBHASHES               5
#define BLOOMFILTERBITSIZE      (FILTERSIZE * 8)
#define MAXBLOCKS               192 //128
#define MINBLOCKS				10 //if a Bloom filter has less than MINBLOCKS it is skipped
//#define SKIPPED_BYTES           BLOCK_SIZE/4
#define SKIPPED_BYTES           0
#define PROBABILITY             0.99951172 //Attention: 1 - ( 1/BLOOMFILTERBITSIZE )

#define MIN(a,b) (a < b ? a : b)
#define MAX(a,b) (a > b ? a : b)

typedef unsigned long long  uint64; 
typedef unsigned char       uchar;
typedef unsigned int        uint32;

//#define MIN_RUN                 2  //origin 8  //greater or equal is a TP

extern int BLOCK_SIZE;
extern int MIN_RUN;

#endif	/* CONFIG_H */

