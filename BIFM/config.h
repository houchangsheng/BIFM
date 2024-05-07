#ifndef CONFIG_H
#define	CONFIG_H

#define ROLLING_WINDOW          7  //origin 7
#define BLOCK_SIZE              64  //origin 64
//#define WINNOWING_WINDOW        64  //32 or 64
//#define SHINGLING_BYTES         4
//#define DOWN_SAMPLING_TH        40
#define SKIPPED_BYTES           0  //BLOCK_SIZE/3  //origin BLOCK_SIZE/3
#define MIN_ENTROPY             0.0  //2.5

#define MIN_RUN                 2  //origin 8  //greater or equal is a TP

//#define BF_SIZE_IN_BYTES        33554432  //origin 33554432 //16384 //33554432 //Filter size Bytes 2^25
//#define BF_SIZE_IN_BYTES        1024 * 1024  //ok
#define SUBHASHES               6  //origin 64

//do not use
//#define SKIP_FIRST              1  //Skip first block which often contains header info
//#define SKIP_LAST               1  //Skip last block which often contains footer info
//#define PACKET_SIZE             1460
//#define UNSET_BITS_THRES        15  //256 is ignore

typedef unsigned long long  uint64; 
typedef unsigned char       uchar;
typedef unsigned int        uint32;
typedef unsigned short      ushort16;
typedef unsigned int        uint256[8];
typedef unsigned long long  uint256r[5];

inline uint64 upperpower2(uint64 x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16; 
    x |= x >> 32; 
    x++;
    return x;
}

inline uint64 lowerpower2(uint64 x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16; 
    x |= x >> 32; 
    x++;
    x = x >> 1;
    return x;
}

extern int BF_SIZE_IN_BYTES;
extern int filter_number;

extern int WINNOWING_WINDOW;
extern int SHINGLING_BYTES;
extern int DOWN_SAMPLING_TH;

extern int check_threshold;

#endif	/* CONFIG_H */

