#include "hashing.h"

#define get16bits(d) (*((const uint16_t *) (d)))

// SuperFastHash aka Hsieh Hash, License: GPL 2.0
uint32_t SuperFastHash(const void *buf, size_t len)
{
    const char* data = (const char*) buf;
    uint32_t hash = len, tmp;
    int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
    case 3: hash += get16bits (data);
        hash ^= hash << 16;
        hash ^= data[sizeof (uint16_t)] << 18;
        hash += hash >> 11;
        break;
    case 2: hash += get16bits (data);
        hash ^= hash << 11;
        hash += hash >> 17;
        break;
    case 1: hash += *data;
        hash ^= hash << 10;
        hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

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

BitmapTable** hashBufferToBF(char* flow_ID, BLOOMFILTER** bf, BitmapTable** bitmap_table, int& flow_num, unsigned char* byte_buffer, unsigned int bytes_read)
{
	unsigned int i, j;
	unsigned int last_block_index = 0;
	uint32 rValue = 0;

	/*we need this arrays for our extended rollhash function*/
	uchar window[ROLLING_WINDOW] = { 0 };
	uint32 rhData[4] = { 0 };

	unsigned int* hash_val;
	unsigned int* hash_val_f;
	unsigned int block_size;

	int row_idx = -1;
	for (i = 0; i < flow_num; i++)
	{
		if (bitmap_table[i]->isSameFlow(flow_ID))
		{
			row_idx = i;
			break;
		}
	}
	if (row_idx == -1)
	{
		bitmap_table = (BitmapTable**)realloc(bitmap_table, (flow_num + 1) * sizeof(BitmapTable*));
		bitmap_table[flow_num] = new BitmapTable((filter_number + 7) / 8);
		bitmap_table[flow_num]->setFlowID(flow_ID);
		row_idx = flow_num;
		flow_num++;
	}

	// if bytes_read < WINNOWING_WINDOW, then winnowing_list[WINNOWING_WINDOW-1] overflow.
	/* modified 2023 10 27 */
	if(bitmap_table[row_idx]->getPacketCacheLen() + bytes_read <= ROLLING_WINDOW + WINNOWING_WINDOW - 1)
	{
		bitmap_table[row_idx]->addPacketCache(byte_buffer, bytes_read);
		return bitmap_table;
	}
	/* modified 2023 10 27 */

	unsigned char* byte_buffer_tmp;
	unsigned int bytes_read_tmp;

	if(bitmap_table[row_idx]->getPacketCacheLen() != 0)
	{
		byte_buffer_tmp = new unsigned char[bytes_read + bitmap_table[row_idx]->getPacketCacheLen()];
		memset(byte_buffer_tmp, 0, sizeof(unsigned char) * (bytes_read + bitmap_table[row_idx]->getPacketCacheLen()));
		memcpy(byte_buffer_tmp, bitmap_table[row_idx]->getPacketCache(), bitmap_table[row_idx]->getPacketCacheLen());
		memcpy(byte_buffer_tmp+bitmap_table[row_idx]->getPacketCacheLen(), byte_buffer, bytes_read);

		/* modified 2023 10 27 */
		bytes_read_tmp = bytes_read + bitmap_table[row_idx]->getPacketCacheLen();
		/* modified 2023 10 27 */
	}
	else
	{
		byte_buffer_tmp = new unsigned char[bytes_read];
		memset(byte_buffer_tmp, 0, sizeof(unsigned char) * bytes_read);
		memcpy(byte_buffer_tmp, byte_buffer, bytes_read);

		/* modified 2023 10 27 */
		bytes_read_tmp = bytes_read;
		/* modified 2023 10 27 */
	}

	/* modified 2023 10 27 */
	/* --- rValue_list and winnowing_list --- */
	uint32* rValue_list = (uint32*)calloc(bytes_read_tmp, sizeof(uint32));
	memset(rValue_list, 0, sizeof(uint32) * bytes_read_tmp);

	//0: not bound; 1: trusted bound; -1: not hit bound; -2: untrusted bound;
	int* winnowing_list = (int*)calloc(bytes_read_tmp, sizeof(int));
	memset(winnowing_list, 0, sizeof(int) * bytes_read_tmp);
	/* modified 2023 10 27 */

	uint32 maxValue = 0;
	int maxIndex = 0;

	/* modified 2023 10 27 */
	for (i = 0; i < bytes_read_tmp; i++)
	{
		rValue = roll_hashx(byte_buffer_tmp[i], window, rhData);
	/* modified 2023 10 27 */
		rValue_list[i] = rValue;
		if(i < ROLLING_WINDOW)
		{
			rValue_list[i] = 0;
		}
		
		int window_left = (i - WINNOWING_WINDOW + 1) > 0 ? (i - WINNOWING_WINDOW + 1) : 0;

		if(maxIndex >= window_left)
		{
			if(rValue_list[i] >= maxValue)
			{
				maxValue = rValue_list[i];
				maxIndex = i;
			}
		}
		else
		{
			maxValue = 0;
			maxIndex = 0;
			for(j = window_left; j <= i; j++)
			{
				if(rValue_list[j] >= maxValue)
				{
					maxValue = rValue_list[j];
					maxIndex = j;
				}
			}	
		}
		
		winnowing_list[maxIndex] = 1;
	}

	for (i = WINNOWING_WINDOW + ROLLING_WINDOW - 1; i > 0; i--)
	{
		if(winnowing_list[i-1] == 1)
		{
			winnowing_list[i-1] = -3;
		}
	}
	for (i = WINNOWING_WINDOW + ROLLING_WINDOW - 1; i > 0; i--)
	{
		if(winnowing_list[i-1] == -3)
		{
			winnowing_list[i-1] = 1;
			break;
		}
	}
	/* --- rValue_list and winnowing_list --- */

	/* modified 2023 10 27 */
	for (i = 0; i < bytes_read_tmp; i++)
	/* modified 2023 10 27 */
	{
		if (winnowing_list[i] == 1)
		{
			block_size = i - last_block_index;

			if(block_size + 1 <= DOWN_SAMPLING_TH)
			{
				last_block_index = i + 1;
				/* modified 2023 10 27 */
				if (i + SKIPPED_BYTES < bytes_read_tmp)
				/* modified 2023 10 27 */
				{
					i += SKIPPED_BYTES;
				}
				continue;
			}

			/* modified 2023 10 27 */
			unsigned int block_size_shingle = ( (i + SHINGLING_BYTES) < bytes_read_tmp) ? (block_size + 1 + SHINGLING_BYTES) : (bytes_read_tmp - 1 - last_block_index + 1);

			unsigned char* buffer = (unsigned char*)calloc(block_size_shingle, sizeof(unsigned char));
			memset(buffer, 0, sizeof(unsigned char) * block_size_shingle);
			memcpy(buffer, byte_buffer_tmp + last_block_index, block_size_shingle);
			hash_val = fnv256Bit(byte_buffer_tmp, last_block_index, last_block_index + block_size_shingle - 1);


			unsigned char* buffer_tmp = (unsigned char*)calloc(block_size_shingle + strlen(flow_ID), sizeof(unsigned char));
			memset(buffer_tmp, 0, sizeof(unsigned char) * (block_size_shingle + strlen(flow_ID)));
			memcpy(buffer_tmp, flow_ID, strlen(flow_ID));
			memcpy(buffer_tmp+strlen(flow_ID), byte_buffer_tmp + last_block_index, block_size_shingle);
			hash_val_f = fnv256Bit(buffer_tmp, 0, block_size_shingle + strlen(flow_ID) - 1);
			/* modified 2023 10 27 */

			//hash选择filter
			int filter_id = SuperFastHash((const char*)buffer, block_size_shingle) % filter_number;
			bitmap_table[row_idx]->setBit(filter_id);

			add_hash_to_bloomfilter(bf[filter_id], hash_val);
			add_hash_to_bloomfilter(bf[filter_id], hash_val_f);

			free(buffer);
			free(buffer_tmp);
			free(hash_val);
			free(hash_val_f);

			last_block_index = i + 1;
			/* modified 2023 10 27 */
			if (i + SKIPPED_BYTES < bytes_read_tmp)
			/* modified 2023 10 27 */
			{
				i += SKIPPED_BYTES;
			}
		}
		hash_val = 0;
		hash_val_f = 0;
		block_size = 0;
	}

	bitmap_table[row_idx]->setPacketCache(&byte_buffer_tmp[bytes_read_tmp - (ROLLING_WINDOW + WINNOWING_WINDOW - 1)], ROLLING_WINDOW + WINNOWING_WINDOW - 1);

	return bitmap_table;
}

unsigned int* checkBufferInBF(char* flow_ID, BLOOMFILTER** bf, int threshold_b, int threshold, BitmapTable** bitmap_table, int flow_num, unsigned char* byte_buffer, unsigned int bytes_read)
{
	unsigned int* results_summary = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary, 0, sizeof(unsigned int) * 4);

	unsigned int* results_summary2 = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary2, 0, sizeof(unsigned int) * 4);

	/* modified 2023 10 26 */
	unsigned int* results = (unsigned int*)calloc(5, sizeof(unsigned int));  // 0: excerpt_find; 1: flow_match; 2: false_positive; 3: false_positive_no_true_positive; 4: total_false_positive;
	memset(results, 0, sizeof(unsigned int) * 5);
	/* modified 2023 10 26 */

	unsigned int i, j;
	unsigned int last_block_index = 0;
	uint32 rValue = 0;

	/*we need this arrays for our extended rollhash function*/
	uchar window[ROLLING_WINDOW] = { 0 };
	uint32 rhData[4] = { 0 };

	unsigned int* hash_val;
	unsigned int* hash_val_f;
	unsigned int block_size;

	BitmapTable* bm_tmp = new BitmapTable((filter_number + 7) / 8);

	/* --- rValue_list and winnowing_list --- */
	uint32* rValue_list = (uint32*)calloc(bytes_read, sizeof(uint32));
	memset(rValue_list, 0, sizeof(uint32) * bytes_read);

	//0: not bound; 1: trusted bound; -1: not hit bound; -2: untrusted bound;
	int* winnowing_list = (int*)calloc(bytes_read, sizeof(int));
	memset(winnowing_list, 0, sizeof(int) * bytes_read);

	uint32 maxValue = 0;
	int maxIndex = 0;

	for (i = 0; i < bytes_read; i++)
	{
		rValue = roll_hashx(byte_buffer[i], window, rhData);
		rValue_list[i] = rValue;
		if(i < ROLLING_WINDOW)
		{
			rValue_list[i] = 0;
		}
		
		int window_left = (i - WINNOWING_WINDOW + 1) > 0 ? (i - WINNOWING_WINDOW + 1) : 0;

		if(maxIndex >= window_left)
		{
			if(rValue_list[i] >= maxValue)
			{
				maxValue = rValue_list[i];
				maxIndex = i;
			}
		}
		else
		{
			maxValue = 0;
			maxIndex = 0;
			for(j = window_left; j <= i; j++)
			{
				if(rValue_list[j] >= maxValue)
				{
					maxValue = rValue_list[j];
					maxIndex = j;
				}
			}	
		}
		
		winnowing_list[maxIndex] = 1;
	}

	for (i = WINNOWING_WINDOW + ROLLING_WINDOW - 1; i > 0; i--)
	{
		if(winnowing_list[i-1] == 1)
		{
			winnowing_list[i-1] = -3;
		}
	}
	for (i = WINNOWING_WINDOW + ROLLING_WINDOW - 1; i > 0; i--)
	{
		if(winnowing_list[i-1] == -3)
		{
			winnowing_list[i-1] = 1;
			break;
		}
	}
	/* --- rValue_list and winnowing_list --- */

	bool set_flag = false;

	for (i = 0; i < bytes_read; i++)
	{
		if (winnowing_list[i] == 1)
		{
			if(!set_flag)
			{
				set_flag = true;
				last_block_index = i + 1;
				if (i + SKIPPED_BYTES < bytes_read)
				{
					i += SKIPPED_BYTES;
				}
				continue;
			}
			if( (i + SHINGLING_BYTES) >= bytes_read )  //ignore the last block
			{
				continue;
			}
			results_summary[0]++;  //total block
			block_size = i - last_block_index;

			if(block_size + 1 <= DOWN_SAMPLING_TH)
			{
				/* modified 2023 12 23 */
				results_summary[1]++;
				//results_summary[2]++;  //trusted block
				/* modified 2023 12 23 */
				last_block_index = i + 1;
				if (i + SKIPPED_BYTES < bytes_read)
				{
					i += SKIPPED_BYTES;
				}
				continue;
			}

			//unsigned int block_size_shingle = ( (i + SHINGLING_BYTES) < bytes_read) ? (block_size + 1 + SHINGLING_BYTES) : (bytes_read - 1 - last_block_index + 1);
			unsigned int block_size_shingle = block_size + 1 + SHINGLING_BYTES;

			unsigned char* buffer = (unsigned char*)calloc(block_size_shingle, sizeof(unsigned char));
			memset(buffer, 0, sizeof(unsigned char) * block_size_shingle);
			memcpy(buffer, byte_buffer + last_block_index, block_size_shingle);
			hash_val = fnv256Bit(byte_buffer, last_block_index, last_block_index + block_size_shingle - 1);

			//hash选择filter
			int filter_id = SuperFastHash((const char*)buffer, block_size_shingle) % filter_number;

			if (is_in_bloom(bf[filter_id], hash_val) == 1)
			{
				results_summary[1]++;  //hit block
				bm_tmp->setBit(filter_id);
				results_summary[2]++;  //trusted block
			}

			free(buffer);
			free(hash_val);

			last_block_index = i + 1;
			if (i + SKIPPED_BYTES < bytes_read)
			{
				i += SKIPPED_BYTES;
			}
		}
		hash_val = 0;
		block_size = 0;
	}

	if (results_summary[1] >= threshold_b)
	{
		results[0] = 1;
		printf("---- fine the excerpt: %i of %i (longest run: %i)\n", results_summary[1], results_summary[0], results_summary[2]);

		char* flow_identifier;

		/* modified 2023 10 26 */
		int fc_results[flow_num] = { threshold };
		for (j = 0; j < flow_num; j++)
		{
			fc_results[j] = bitmap_table[j]->fuzzy_compare2(bm_tmp, threshold);
			//std::cout << fc_results[j] << " ";			
		}
		//std::cout << "\n";
		bool check_flag = false;
		/* modified 2024 01 06 */
		bool check_flag_final = false;
		/* modified 2024 01 06 */

		bool hit_flag = false;
		for (int th_idx = 0; th_idx <= threshold; th_idx++)
		{
			if(check_flag)
			{
				/* modified 2024 01 06 */
				if(check_flag_final)
				{
					break;
				}
				else
				{
					check_flag_final = true;
				}
				/* modified 2024 01 06 */
			}
		/* modified 2023 10 26 */

		for (j = 0; j < flow_num; j++)
		{

			/* modified 2023 10 26 */
			//if (bitmap_table[j]->compare(bm_tmp))
			if (fc_results[j] == th_idx)
			{
				int fuzzy_count = 0;
			/* modified 2023 10 26 */

				memset(results_summary2, 0, sizeof(unsigned int) * 4);

				flow_identifier = bitmap_table[j]->getFlowID();

				last_block_index = 0;
				memset(window, 0, sizeof(uchar) * ROLLING_WINDOW);
				memset(rhData, 0, sizeof(uint32) * 4);

				set_flag = false;

				for (i = 0; i < bytes_read; i++)
				{
					if ( (winnowing_list[i] == 1) )
					{
						if(!set_flag)
						{
							set_flag = true;
							last_block_index = i + 1;
							if (i + SKIPPED_BYTES < bytes_read)
							{
								i += SKIPPED_BYTES;
							}
							continue;
						}
						if( (i + SHINGLING_BYTES) >= bytes_read )
						{
							continue;
						}
						results_summary2[0]++;
						block_size = i - last_block_index;

						if(block_size + 1 <= DOWN_SAMPLING_TH)
						{
							/* modified 2023 12 23 */
							//results_summary2[1]++;
							/* modified 2023 12 23 */
							last_block_index = i + 1;
							if (i + SKIPPED_BYTES < bytes_read)
							{
								i += SKIPPED_BYTES;
							}
							continue;
						}

						//unsigned int block_size_shingle = ( (i + SHINGLING_BYTES) < bytes_read) ? (block_size + 1 + SHINGLING_BYTES) : (bytes_read - 1 - last_block_index + 1);
						unsigned int block_size_shingle = block_size + 1 + SHINGLING_BYTES;

						unsigned char* buffer = (unsigned char*)calloc(block_size_shingle, sizeof(unsigned char));
						memset(buffer, 0, sizeof(unsigned char) * block_size_shingle);
						memcpy(buffer, byte_buffer + last_block_index, block_size_shingle);
						hash_val = fnv256Bit(byte_buffer, last_block_index, last_block_index + block_size_shingle - 1);


						unsigned char* buffer_tmp = (unsigned char*)calloc(block_size_shingle + strlen(flow_identifier), sizeof(unsigned char));
						memset(buffer_tmp, 0, sizeof(unsigned char) * (block_size_shingle + strlen(flow_identifier)));
						memcpy(buffer_tmp, flow_identifier, strlen(flow_identifier));
						memcpy(buffer_tmp+strlen(flow_identifier), byte_buffer + last_block_index, block_size_shingle);
						hash_val_f = fnv256Bit(buffer_tmp, 0, block_size_shingle + strlen(flow_identifier) - 1);

						//hash选择filter
						int filter_id = SuperFastHash((const char*)buffer, block_size_shingle) % filter_number;

						/* modified 2023 10 26 */
						/*if ( (is_in_bloom(bf[filter_id], hash_val) == 1) && (is_in_bloom(bf[filter_id], hash_val_f) == 1))
						{
							results_summary2[1]++;
						}*/
						if ( (is_in_bloom(bf[filter_id], hash_val) == 1) && (is_in_bloom(bf[filter_id], hash_val_f) == 1))
						{
							results_summary2[1]++;
						}
						else if(!bitmap_table[j]->checkBit(filter_id))
						{
							fuzzy_count += 1;
						}
						/* modified 2023 10 26 */

						free(buffer);
						free(buffer_tmp);
						free(hash_val);
						free(hash_val_f);

						last_block_index = i + 1;
						if (i + SKIPPED_BYTES < bytes_read)
						{
							i += SKIPPED_BYTES;
						}
					}

					hash_val = 0;
					hash_val_f = 0;
					block_size = 0;
				}

				/* modified 2023 10 26 */
				//if (results_summary2[1] >= results_summary[2])
				/* modified 2024 01 08 */
				fuzzy_count = (fuzzy_count < th_idx) ? fuzzy_count : th_idx;  //need test
				/* modified 2024 01 08 */
				if (results_summary2[1] + fuzzy_count >= results_summary[2])
				{
					check_flag = true;
				/* modified 2023 10 26 */
					if(strcmp(flow_identifier, flow_ID) == 0)
					{
						results[1] = 1;
						/* modified 2023 10 26 */
						hit_flag = true;
						/* modified 2023 10 26 */
						printf("-------- match flow %s: %i of %i (longest run: %i)    true\n", flow_identifier, results_summary2[1], results_summary2[0], results_summary2[2]);
					}
					else
					{
						/* modified 2023 10 26 */
						//results[2] = 1;
						//results[3] += 1;
						results[2] = 1;
						results[4] += 1;
						if(!hit_flag)
						{
							results[3] = 1;
						}
						/* modified 2023 10 26 */
						printf("-------- match flow %s: %i of %i (longest run: %i)    false\n", flow_identifier, results_summary2[1], results_summary2[0], results_summary2[2]);
					}
				}
			}
		}

		/* modified 2023 10 26 */
		}
		if(hit_flag)
		{
			results[3] = 0;
		}
		/* modified 2023 10 26 */
		/* modified 2024 01 25 */
		if(results[3] == 1)
		{
			results[2] = 0;
		}
		/* modified 2024 01 25 */
	}

	free(results_summary);
	free(results_summary2);

	return results;
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
