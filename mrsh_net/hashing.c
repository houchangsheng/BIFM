#include "hashing.h"

uint32 roll_hashx(unsigned char c, uchar window[], uint32 rhData[])
{
	uint32 t = rhData[0] % ROLLING_WINDOW;

	rhData[2] -= rhData[1];
	rhData[2] += (ROLLING_WINDOW * c);

	rhData[1] += c;
	rhData[1] -= window[t];

	window[t] = c;
	rhData[0]++;

	rhData[3] = (rhData[3] << 5); //& 0xFFFFFFFF;
	rhData[3] ^= c;

	return rhData[1] + rhData[2] + rhData[3];
}

//Depending on the fourth parameter it fills the Bloom filter or it compares File against Bloom filter
//doWhat: 1 = hashAndAdd; 2 = hashAndCompare;
unsigned int* hashFileAndDo(BLOOMFILTER* bf, unsigned char* byte_buffer, int doWhat, unsigned int start, unsigned int stop)
{
	unsigned int i;
	uint32 rValue;

	unsigned int randomness = 0;

	unsigned int last_block_index = start;
	float entropy_val = 0.0, tmp_entro = 0.0;

	unsigned int* frequencyArray = (unsigned int*)calloc(256, sizeof(unsigned int));
	memset(frequencyArray, 0, sizeof(unsigned int) * 256);

	unsigned int* results_summary = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary, 0, sizeof(unsigned int) * 4);

	unsigned int* hash_val;
	unsigned int skip_counter = 0;

	/*we need this arrays for our extended rollhash function*/
	uchar window[ROLLING_WINDOW] = { 0 };
	uint32 rhData[4] = { 0 };

	//run through all bytes
	for (i = start; i < stop; i++)
	{
		//update frequency array for entropy
		frequencyArray[byte_buffer[i]]++;

		//Randomness
		if (i + 1 < stop && abs(byte_buffer[i] - byte_buffer[i + 1]) <= 1)
		{
			randomness++;
		}

		//skip rolling hash if chunk is too small
		/*if (skip_counter++ < SKIPPED_BYTES)
		{
			continue;
		}*/

		//build rolling hash
		rValue = roll_hashx(byte_buffer[i], window, rhData);

		//check for end of chunk
		if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1)
		{
			//a chunk was found, so increase counter
			results_summary[0]++;

			//calculate entropy of piece, Hou Changsheng modified "i - last_block_index" to "i - last_block_index + 1"
			entropy_val = (double)entropy(frequencyArray, i - last_block_index + 1);

			/*if (entropy_val == tmp_entro)  //why??? from Hou Changsheng
			{
				continue;
			}*/

			//if entropy is over our MIN_ENTROPY, hash and add ....
/*			if ((entropy_val >= MIN_ENTROPY) && (randomness * 3 < (i - last_block_index)))
			{*/
				//hash the chunk and add hash to bloom filter
				hash_val = fnv256Bit(byte_buffer, last_block_index, i);

				//check whether we are in comparison mode or checking mode
				if (doWhat == 1)
				{
					add_hash_to_bloomfilter(bf, hash_val);
				}
				else if (doWhat == 2)
				{
					if (createResultsSummary(bf, hash_val, results_summary) && results_summary[2] > 5)
					{
						//printf("Randomness: %i < %i ;    Entropy: %f ;\n", randomness * 3, i - last_block_index, entropy_val);
						//Hou Changsheng modified "i - last_block_index" to "i - last_block_index + 1"
						//hexDump("Byte_buffer", &byte_buffer[last_block_index], i - last_block_index + 1);
					}
				}
				free(hash_val);
/*			}
			else
			{
				//...otherwise reset counter for longest run
				results_summary[3] = 0;
			}*/

			//set stuff for next round
			tmp_entro = entropy_val;
			last_block_index = i + 1;

			//reset counter
			skip_counter = 0;
			randomness = 0;
		}
	}

	free(frequencyArray);
	return results_summary;
}

unsigned int* hashFileAndDo(char* flow_ID, BLOOMFILTER* bf, unsigned char* byte_buffer, int doWhat, unsigned int start, unsigned int stop)
{
	unsigned int i;
	uint32 rValue;

	unsigned int randomness = 0;

	unsigned int last_block_index = start;
	float entropy_val = 0.0, tmp_entro = 0.0;

	unsigned int* frequencyArray = (unsigned int*)calloc(256, sizeof(unsigned int));
	memset(frequencyArray, 0, sizeof(unsigned int) * 256);

	unsigned int* results_summary = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary, 0, sizeof(unsigned int) * 4);

	unsigned int* hash_val;
	unsigned int skip_counter = 0;

	/*we need this arrays for our extended rollhash function*/
	uchar window[ROLLING_WINDOW] = { 0 };
	uint32 rhData[4] = { 0 };

	//run through all bytes
	for (i = start; i < stop; i++)
	{
		//update frequency array for entropy
		frequencyArray[byte_buffer[i]]++;

		//Randomness
		if (i + 1 < stop && abs(byte_buffer[i] - byte_buffer[i + 1]) <= 1)
		{
			randomness++;
		}

		//skip rolling hash if chunk is too small
		/*if (skip_counter++ < SKIPPED_BYTES)
		{
			continue;
		}*/

		//build rolling hash
		rValue = roll_hashx(byte_buffer[i], window, rhData);

		//check for end of chunk
		if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1)
		{
			//a chunk was found, so increase counter
			results_summary[0]++;

			//calculate entropy of piece, Hou Changsheng modified "i - last_block_index" to "i - last_block_index + 1"
			entropy_val = (double)entropy(frequencyArray, i - last_block_index + 1);

/*			if (entropy_val == tmp_entro)  //why??? from Hou Changsheng
			{
				continue;
			}

			//if entropy is over our MIN_ENTROPY, hash and add ....
			if ((entropy_val >= MIN_ENTROPY) && (randomness * 3 < (i - last_block_index)))
			{*/
				//hash the chunk and add hash to bloom filter
				hash_val = fnv256Bit(byte_buffer, last_block_index, i);

				unsigned char* buffer_tmp = (unsigned char*)calloc(i - last_block_index + 1 + strlen(flow_ID), sizeof(unsigned char));
				memset(buffer_tmp, 0, sizeof(unsigned char) * (i - last_block_index + 1 + strlen(flow_ID)));
				memcpy(buffer_tmp, flow_ID, strlen(flow_ID));
				memcpy(buffer_tmp+strlen(flow_ID), byte_buffer + last_block_index, i - last_block_index + 1);

				//unsigned int* hash_val_flow_ID = fnv256Bit(buffer_tmp, 0, i - last_block_index + 1 + strlen(flow_ID));
				unsigned int* hash_val_flow_ID = fnv256Bit(buffer_tmp, 0, i - last_block_index + strlen(flow_ID));

				//check whether we are in comparison mode or checking mode
				if (doWhat == 1)
				{
					add_hash_to_bloomfilter(bf, hash_val);
					add_hash_to_bloomfilter(bf, hash_val_flow_ID);
				}
				else if (doWhat == 2)
				{
					if (createResultsSummary(bf, hash_val, hash_val_flow_ID, results_summary) && results_summary[2] > 5)
					{
						//printf("Randomness: %i < %i ;    Entropy: %f ;\n", randomness * 3, i - last_block_index, entropy_val);
						//Hou Changsheng modified "i - last_block_index" to "i - last_block_index + 1"
						//hexDump("Byte_buffer", &byte_buffer[last_block_index], i - last_block_index + 1);
					}
				}
				free(hash_val);
				free(buffer_tmp);
				free(hash_val_flow_ID);
/*			}
			else
			{
				//...otherwise reset counter for longest run
				results_summary[3] = 0;
			}*/

			//set stuff for next round
			tmp_entro = entropy_val;
			last_block_index = i + 1;

			//reset counter
			skip_counter = 0;
			randomness = 0;
		}
	}

	free(frequencyArray);
	return results_summary;
}

double entropy(unsigned int freqArray[], int size)
{
	double e = 0.0;
	double f = 0.0;
	int i = 0;
	for (i = 0; i <= 255; i++)
	{
		if (freqArray[i] > 0)
		{
			f = (double)freqArray[i] / size;
			e -= f * log2(f);
			freqArray[i] = 0;  //reset
		}
	}
	return e;
}

int createResultsSummary(BLOOMFILTER* bf, uint256 hash_val, unsigned int* results_summary)
{
	if (is_in_bloom(bf, hash_val) == 1)
	{
		results_summary[1]++;  //counter for found chunks
		results_summary[3]++;
		//check if there is a longer run
		if (results_summary[3] > results_summary[2])
		{
			results_summary[2] = results_summary[3];
		}
		return 1;
	}
	else
	{
		results_summary[3] = 0;
	}
	return 0;
}

int createResultsSummary(BLOOMFILTER* bf, uint256 hash_val, uint256 hash_val_flow_ID, unsigned int* results_summary)
{
	if (is_in_bloom(bf, hash_val) == 1 && is_in_bloom(bf, hash_val_flow_ID) == 1)
	{
		results_summary[1]++;  //counter for found chunks
		results_summary[3]++;
		//check if there is a longer run
		if (results_summary[3] > results_summary[2])
		{
			results_summary[2] = results_summary[3];
		}
		return 1;
	}
	else
	{
		results_summary[3] = 0;
	}
	return 0;
}

void hexDump(char* desc, void* addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	//Print description
	if (desc != NULL)
	{
		printf("%s:\n", desc);
	}

	for (i = 0; i < len; i++)
	{
		// Multiple of 16 means new line (with line offset).
		if ((i % 16) == 0)
		{
			if (i != 0)
			{
				printf("  %s\n", buff);
			}
			//offset.
			printf("  %04x ", i);
		}

		//Hex
		printf(" %02x", pc[i]);

		//ASCII
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
		{
			buff[i % 16] = '.';
		}
		else
		{
			buff[i % 16] = pc[i];
		}
		buff[(i % 16) + 1] = '\0';
	}

	//the last line
	while ((i % 16) != 0)
	{
		printf("   ");
		i++;
	}
	printf("  %s\n", buff);
}
