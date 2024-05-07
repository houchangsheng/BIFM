#include "hashing.h"
#include "bloomfilter.h"

static int SHIFTOPS;  //FILTER_AS_POW_2 + 3 -> 14
static unsigned long MASK;  //SHIFTOPS in ones    -> 0x1FFFF

void initialize_settings()
{
	SHIFTOPS = (int)log2(BF_SIZE_IN_BYTES) + 3;
	MASK = 0xFFFFFFFFFFFFFFFF >> (64 - SHIFTOPS);
}

//Returns an empty Bloom filter
BLOOMFILTER* init_empty_BF()
{
	BLOOMFILTER* bf;

	bf = (BLOOMFILTER*)malloc(sizeof(BLOOMFILTER));
	bf->bytes_array = new unsigned char[BF_SIZE_IN_BYTES];

	if(!bf->bytes_array)
	{
		fprintf(stderr, "[*] Error in initializing bloom_read \n");
		exit(-1);
	}
	else
	{
		memset(bf->bytes_array, 0, sizeof(unsigned char) * BF_SIZE_IN_BYTES);
	}

	/*if (!(bf = (BLOOMFILTER*)malloc(sizeof(BLOOMFILTER))))
	{
		fprintf(stderr, "[*] Error in initializing bloom_read \n");
		exit(-1);
	}
	else
	{
		memset(bf, 0, sizeof(BLOOMFILTER));
	}*/
	return bf;
}

//Destroy a Bloom filter
void destroy_bf(BLOOMFILTER* bf)
{
	delete [] bf->bytes_array;

	free(bf);
	bf = NULL;
}

/*
 * adds a hash value (eg. FNV) to the Bloom filter
 */
void add_hash_to_bloomfilter(BLOOMFILTER* bf, uint256 hash_val)
{
	uint64 masked_bits, byte_pos;
	short bit_pos;
	unsigned char* test = (unsigned char*)hash_val;

	uint64* p = (uint64*)hash_val;
	uint64 tmpHash = (((uint64)hash_val[1] << 32) ^ hash_val[0]);

	//add the hash value to the bloom filter
	for (int j = 0; j < SUBHASHES; j++)
	{
		//get least significant bytes and use one relevant by AND MASK
		masked_bits = tmpHash & MASK;

		//get byte and bit position
		byte_pos = masked_bits >> 3;
		bit_pos = masked_bits & 0x7;

		//Set bit in BF
		bf->bytes_array[byte_pos] |= (1 << (bit_pos));

		//shift and continue
		p = (uint64*)&test[SHIFTOPS * (j + 1) / 8];
		tmpHash = (*p) >> ((SHIFTOPS * (j + 1)) % 8);
	}
}

void unset_bit(BLOOMFILTER* bf, unsigned int bit)
{
	unsigned int byte_pos;
	short bit_pos;

	//get byte and bit position
	byte_pos = bit / 8;
	bit_pos = bit % 8;

	bf->bytes_array[byte_pos] &= ~(1 << bit_pos);
}

short is_in_bloom(BLOOMFILTER* bf, uint256 hash_val)
{
	uint64 masked_bits, byte_pos;
	short bit_pos;
	unsigned char* test = (unsigned char*)hash_val;

	uint64* p = (uint64*)hash_val;
	uint64 tmpHash = (((uint64)hash_val[1] << 32) ^ hash_val[0]);

	for (int j = 0; j < SUBHASHES; j++)
	{
		//get least significant bytes and use one relevant by AND MASK
		masked_bits = tmpHash & MASK;

		//get byte and bit position
		byte_pos = masked_bits >> 3;
		bit_pos = masked_bits & 0x7;

        	//if position in BF is zero then element isn't in BF
		if (((bf->bytes_array[byte_pos] >> bit_pos) & 0x1) != 1)
		{
			return 0;
		}

        	//shift and continue
		p = (uint64*)&test[SHIFTOPS * (j + 1) / 8];
		tmpHash = (*p) >> ((SHIFTOPS * (j + 1)) % 8);
	}
	return 1;
}

void print_bf(BLOOMFILTER* bf)
{
	int j;
	FILE* fp = fopen("myDB", "wb");

	for (j = 0; j < BF_SIZE_IN_BYTES; j++)
	{
		//printf("%c", bf->bytes_array[j]);
		fwrite(&bf->bytes_array[j], sizeof(bf->bytes_array[j]), 1, fp);
	}
	//hexDump(NULL, bf, BF_SIZE_IN_BYTES);
	fclose(fp);
}

void readFileToBF(const char* filename, BLOOMFILTER* bf)
{
	int i;
	FILE* fp = fopen(filename, "rb");
	if (fp != 0)
	{
		//for (i = 0; fread(&bf[i], sizeof(bf[i]), 1, fp) == 1; i++)
		for (i = 0; fread(&bf->bytes_array[i], sizeof(bf->bytes_array[i]), 1, fp) == 1; i++)
			;
		fclose(fp);
	}
}
