#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cmath>
#include <cassert>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#include <unistd.h>
#include <dirent.h>

#include "timing.h"
#include "config.h"
#include "fnv.h"
#include "hashutil.h"
#include "cuckoofilter.h"

std::string experiment_record = "mrsh_cf";

int BLOCK_SIZE = 64;
int MIN_RUN = 2;

#define BitPerTag 8

class mrsh_CF
{
	size_t total_items;
	std::uint64_t total_chunks = 0;
	std::uint64_t insert_errors = 0;
	std::uint64_t insert_errors_flow = 0;

public:
	CuckooFilter<char[], BitPerTag>* filter;

	inline std::uint64_t getTotalChunks()
	{
		return this->total_chunks;
	}
	inline std::uint64_t getErrorChunks()
	{
		return this->insert_errors;
	}

	//mrsh_CF(const size_t total_items);
	mrsh_CF(const size_t memory_overhead);
	~mrsh_CF();

	std::uint32_t roll_hashx(std::uint8_t c, std::uint8_t window[], std::uint32_t rhData[]);
	void hashBufferToCuckooFilter(char* flow_ID, unsigned char* byte_buffer, std::uint64_t bytes_read);
	void copyBlockToBuffer(unsigned char* byte_buffer, char* buff, std::uint32_t start, std::uint32_t stop);
	std::uint64_t generateIndexTagHash(const char* buff, std::uint32_t size);
	unsigned int* bufferInCuckooFilter(unsigned char* byte_buffer, std::uint64_t bytes_read);
	unsigned int* bufferInCuckooFilter(char* flow_ID, unsigned char* byte_buffer, std::uint64_t bytes_read);

	void writeFingerprint();
	void readFingerprint();
	void compareFingerprints(mrsh_CF* obj);
	void getCuckooFilterInfo();
	void printBuff(char* buff, std::uint32_t size);
};

/*mrsh_CF::mrsh_CF(const size_t total_items)
{
	filter = new CuckooFilter<char[], 32>(total_items);
	this->total_items = total_items;
}*/

mrsh_CF::mrsh_CF(const size_t memory_overhead)
{
	filter = new CuckooFilter<char[], BitPerTag>(memory_overhead);
	this->total_items = 0;
}

mrsh_CF::~mrsh_CF()
{
	delete filter;
}

std::uint32_t mrsh_CF::roll_hashx(std::uint8_t c, std::uint8_t window[], std::uint32_t rhData[])
{
	rhData[2] -= rhData[1];
	rhData[2] += (ROLLING_WINDOW * c);

	rhData[1] += c;
	rhData[1] -= window[rhData[0] % ROLLING_WINDOW];

	window[rhData[0] % ROLLING_WINDOW] = c;
	rhData[0]++;

	/* The original spamsum AND'ed this value with 0xFFFFFFFF which
	   in theory should have no effect. This AND has been removed
           for performance (jk) */
	rhData[3] = (rhData[3] << 5);  //& 0xFFFFFFFF;
	rhData[3] ^= c;

	return rhData[1] + rhData[2] + rhData[3];
}

void mrsh_CF::hashBufferToCuckooFilter(char* flow_ID, unsigned char* byte_buffer, std::uint64_t bytes_read)
{
	std::uint32_t i;
	std::uint32_t last_block_index = 0;
	std::uint64_t rValue;
	std::uint64_t chunkCount = 0;

	/* we need this arrays for extended rollhash function */
	std::uint8_t window[ROLLING_WINDOW] = { 0 };
	std::uint32_t rhData[4] = { 0 };

	std::uint64_t hv, hv2;
	std::uint32_t block_size;

	for (i = 0; i < bytes_read; i++)
	{
		rValue = roll_hashx(byte_buffer[i], window, rhData);
		if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1)
		{
			total_chunks++;
			block_size = i - last_block_index;
			char* buff = new char[block_size + 1];
			copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
			//hv = generateIndexTagHash(buff, block_size);
			hv = generateIndexTagHash(buff, block_size + 1);

			char* buff2 = new char[block_size + 1 + strlen(flow_ID)];
			copyBlockToBuffer((unsigned char*)flow_ID, buff2, 0, strlen(flow_ID) - 1);
			copyBlockToBuffer(byte_buffer, buff2+strlen(flow_ID), last_block_index, i);
			hv2 = generateIndexTagHash(buff2, block_size + 1 + strlen(flow_ID));

			if (filter->Add(hv) != Ok)
			{
				++insert_errors;
				std::cout << "\n ------------------------" << std::endl;
				std::cout<<"Error in adding hash to cuckoo filter \n";
				//printBuff(buff, block_size);
			}
			if (filter->Add(hv2) != Ok)
			{
				++insert_errors_flow;
			}

			last_block_index = i + 1;
			if (i + SKIPPED_BYTES < bytes_read)
			{
				i += SKIPPED_BYTES;
			}
			delete[] buff;
			delete[] buff2;
		}
		hv = 0;
		block_size = 0;
	}

	/*if (last_block_index != bytes_read)
	{
		total_chunks++;
		i = bytes_read - 1;
		block_size = i - last_block_index;
		char* buff = new char[block_size + 1];
		copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
		//hv = generateIndexTagHash(buff, block_size);
		hv = generateIndexTagHash(buff, block_size + 1);

		char* buff2 = new char[block_size + 1 + strlen(flow_ID)];
		copyBlockToBuffer((unsigned char*)flow_ID, buff2, 0, strlen(flow_ID) - 1);
		copyBlockToBuffer(byte_buffer, buff2+strlen(flow_ID), last_block_index, i);
		hv2 = generateIndexTagHash(buff2, block_size + 1 + strlen(flow_ID));

		if (filter->Add(hv) != Ok)
		{
			++insert_errors;
			std::cout << "\n ------------------------" << std::endl;
			std::cout<<"Error in adding hash to cuckoo filter \n";
		}

		if (filter->Add(hv2) != Ok)
		{
			++insert_errors_flow;
		}

		delete[] buff;
		delete[] buff2;
	}*/

	//std::cout << "flow_ID: " << flow_ID << ", total chunks:" << total_chunks << std::endl;
}

void mrsh_CF::copyBlockToBuffer(unsigned char* byte_buffer, char* buff, std::uint32_t start, std::uint32_t stop)
{
	std::uint32_t j;
	for (j = start; j <= stop; j++)
	{
		buff[j - start] = byte_buffer[j];
	}
}

std::uint64_t mrsh_CF::generateIndexTagHash(const char* buff, std::uint32_t size)
{
	std::string hashed_key = HashUtil::SHA1Hash((const char*)buff, size);
	std::uint64_t hv;
	hv = *((std::uint64_t*)hashed_key.c_str());
	return hv;
}

unsigned int* mrsh_CF::bufferInCuckooFilter(unsigned char* byte_buffer, std::uint64_t bytes_read)
{

	std::uint32_t i;
	std::uint32_t last_block_index = 0;
	std::uint64_t rValue = 0;

	/* we need this arrays for extended rollhash function */
	std::uint8_t window[ROLLING_WINDOW] = { 0 };
	std::uint32_t rhData[4] = { 0 };

	std::uint64_t hv;
	std::uint32_t block_size;

	unsigned int* results_summary = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary, 0, sizeof(unsigned int) * 4);

	for (i = 0; i < bytes_read; i++)
	{
		rValue = roll_hashx(byte_buffer[i], window, rhData);
		if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1)
		{
			results_summary[0]++;
			block_size = i - last_block_index;
			char* buff = new char[block_size + 1];
			copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
			//hv = generateIndexTagHash(buff, block_size);
			hv = generateIndexTagHash(buff, block_size + 1);

			if (filter->Contain(hv) == Ok)
			{
				results_summary[1]++;  //counter for found chunks
				results_summary[3]++;
				//check if there is a longer run
				if (results_summary[3] > results_summary[2])
				{
					results_summary[2] = results_summary[3];
				}
			}
			else
			{
				results_summary[3] = 0;
			}

			last_block_index = i + 1;
			if (i + SKIPPED_BYTES < bytes_read)
			{
				i += SKIPPED_BYTES;
			}
			delete[] buff;
		}
		hv = 0;
		block_size = 0;
	}

	/*if (last_block_index != bytes_read)
	{
		results_summary[0]++;
		i = bytes_read - 1;
		block_size = i - last_block_index;
		char* buff = new char[block_size + 1];
		copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
		//hv = generateIndexTagHash(buff, block_size);
		hv = generateIndexTagHash(buff, block_size + 1);

		if (filter->Contain(hv) == Ok)
		{
			results_summary[1]++;  //counter for found chunks
			results_summary[3]++;
			//check if there is a longer run
			if (results_summary[3] > results_summary[2])
			{
				results_summary[2] = results_summary[3];
			}
		}
		else
		{
			results_summary[3] = 0;
		}

		delete[] buff;
	}*/

	return results_summary;
}

unsigned int* mrsh_CF::bufferInCuckooFilter(char* flow_ID, unsigned char* byte_buffer, std::uint64_t bytes_read)
{

	std::uint32_t i;
	std::uint32_t last_block_index = 0;
	std::uint64_t rValue = 0;

	/* we need this arrays for extended rollhash function */
	std::uint8_t window[ROLLING_WINDOW] = { 0 };
	std::uint32_t rhData[4] = { 0 };

	std::uint64_t hv, hv2;
	std::uint32_t block_size;

	unsigned int* results_summary = (unsigned int*)calloc(4, sizeof(unsigned int));  // 0: total blocks; 1: blocks found; 2: longest run; 3: tmp savings;
	memset(results_summary, 0, sizeof(unsigned int) * 4);

	for (i = 0; i < bytes_read; i++)
	{
		rValue = roll_hashx(byte_buffer[i], window, rhData);
		if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1)
		{
			results_summary[0]++;
			block_size = i - last_block_index;
			char* buff = new char[block_size + 1];
			copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
			//hv = generateIndexTagHash(buff, block_size);
			hv = generateIndexTagHash(buff, block_size + 1);

			char* buff2 = new char[block_size + 1 + strlen(flow_ID)];
			copyBlockToBuffer((unsigned char*)flow_ID, buff2, 0, strlen(flow_ID) - 1);
			copyBlockToBuffer(byte_buffer, buff2+strlen(flow_ID), last_block_index, i);
			hv2 = generateIndexTagHash(buff2, block_size + 1 + strlen(flow_ID));

			if (filter->Contain(hv) == Ok && filter->Contain(hv2) == Ok)
			{
				results_summary[1]++;  //counter for found chunks
				results_summary[3]++;
				//check if there is a longer run
				if (results_summary[3] > results_summary[2])
				{
					results_summary[2] = results_summary[3];
				}
			}
			else
			{
				results_summary[3] = 0;
			}

			last_block_index = i + 1;
			if (i + SKIPPED_BYTES < bytes_read)
			{
				i += SKIPPED_BYTES;
			}
			delete[] buff;
			delete[] buff2;
		}
		hv = 0;
		block_size = 0;
	}

	/*if (last_block_index != bytes_read)
	{
		results_summary[0]++;
		i = bytes_read - 1;
		block_size = i - last_block_index;
		char* buff = new char[block_size + 1];
		copyBlockToBuffer(byte_buffer, buff, last_block_index, i);
		//hv = generateIndexTagHash(buff, block_size);
		hv = generateIndexTagHash(buff, block_size + 1);

		char* buff2 = new char[block_size + 1 + strlen(flow_ID)];
		copyBlockToBuffer((unsigned char*)flow_ID, buff2, 0, strlen(flow_ID) - 1);
		copyBlockToBuffer(byte_buffer, buff2+strlen(flow_ID), last_block_index, i);
		hv2 = generateIndexTagHash(buff2, block_size + 1 + strlen(flow_ID));

		if (filter->Contain(hv) == Ok && filter->Contain(hv2) == Ok)
		{
			results_summary[1]++;  //counter for found chunks
			results_summary[3]++;
			//check if there is a longer run
			if (results_summary[3] > results_summary[2])
			{
				results_summary[2] = results_summary[3];
			}
		}
		else
		{
			results_summary[3] = 0;
		}

		delete[] buff;
		delete[] buff2;
	}*/

	return results_summary;
}

void mrsh_CF::writeFingerprint()
{
	filter->writeFingerprint();
}

void mrsh_CF::readFingerprint()
{
	filter->readFingerprint();
}

void mrsh_CF::compareFingerprints(mrsh_CF* obj)
{
	filter->CompareCF(obj->filter);
}

void mrsh_CF::getCuckooFilterInfo()
{
	std::cout << "Load Factor is: " << filter->Info() << std::endl;
}

void mrsh_CF::printBuff(char* buff, std::uint32_t size)
{
	std::uint32_t i;
	for (i = 0; i < size; i++)
	{
		std::cout << buff[i];
	}
	std::cout << std::endl;
}

struct flows
{
	char flow_key[36];
};

int main(int argc, char** argv)
{
	int i, j, k;
	std::uint64_t dir_size = 3568047512;
	std::uint64_t dataset_size = 3633820402;

	int data_reduction_ratio = 40;
	std::string flow_data = "data_c_aa.txt";
	std::string excerpt_data = "find_seg_500_aa.txt";
	if(argc >= 6)
	{
		data_reduction_ratio = atoi(argv[1]);
		BLOCK_SIZE = atoi(argv[2]);
		MIN_RUN = atoi(argv[3]);
		flow_data = argv[4];
		excerpt_data = argv[5];

		const char *d = "_";
		const char *d2 = ".";
		char *p;
		p = strtok(argv[5], d);
		p = strtok(NULL,d2);

		experiment_record = experiment_record + "_" + argv[2] + "_" + argv[3] + "_" + p + ".txt";
	}
	else
	{
		exit(1);
	}

	int memory_overhead = dataset_size / data_reduction_ratio;


	std::ofstream record(experiment_record.c_str(), std::ios::app);

	time_t now = time(0);
	char* dt = ctime(&now);
	record << "Experiment Time: " << dt << "\n";

	std::cout << "Data Reduction Ratio: " << data_reduction_ratio << "\n\n";
	std::cout << "Flow Data: " << flow_data << "\n";
	std::cout << "Excerpt Data: " << excerpt_data << "\n\n";

	record << "Data Reduction Ratio: " << data_reduction_ratio << "\n\n";
	record << "Flow Data: " << flow_data << "\n";
	record << "Excerpt Data: " << excerpt_data << "\n\n";

	record.close();


	START  //digest start
	//mrsh_CF* obj = new mrsh_CF(dir_size / BLOCK_SIZE / 2);
	mrsh_CF* obj = new mrsh_CF(memory_overhead);

	flows* flow_list = NULL;
	int flow_num = 0;

	std::ifstream ifs_flows(flow_data.c_str(), std::ios::in);
	ifs_flows.seekg(0, std::ios::beg);

	std::string read_buffer;
	int line_num = 0;
	while(std::getline(ifs_flows, read_buffer))
	{
		line_num += 1;
		std::stringstream word(read_buffer);
		std::string src;
		std::string dst;
		std::string proto;
		int bytes_num;
		std::string payload;

		word >> src;
		word >> dst;
		word >> proto;
		word >> bytes_num;
		word >> payload;

		std::string flow_key = src + "-" + dst + "-" + proto;
		char* flow_key_tmp = const_cast<char*>(flow_key.c_str());
		char* payload_tmp = const_cast<char*>(payload.c_str());

		bool isInFlowList = false;
		for(i = 0; i < flow_num; i++)
		{
			if(strcmp(flow_list[i].flow_key, flow_key_tmp) == 0)
			{
				isInFlowList = true;
				break;
			}
		}
		if(!isInFlowList)
		{
			flow_list = (flows*)realloc(flow_list, sizeof(flows)*(flow_num+1));
			memcpy(flow_list[flow_num].flow_key, flow_key.c_str(), flow_key.length());
			flow_list[flow_num].flow_key[flow_key.length()] = '\0';
			flow_num += 1;
		}

		int size = bytes_num;
		unsigned char* buffer = new unsigned char[size];
		memset(buffer, 0, sizeof(unsigned char) * size);

		//std::cout << "Digesting flow: " << flow_key << ", size: " << size << " bytes.\n";
		std::cout << "Digest " << line_num << ": digest packet from flow \"" << flow_key << "\", size: " << size << " bytes.\n";

		for(j = 0; j < size; j++)
		{
			char ch[2];
			ch[0] = payload_tmp[j*2];
			ch[1] = payload_tmp[j*2+1];
			sscanf(ch, "%2hhx", &buffer[j]);
			if(j == 9999 || j == 99999 || j == 999999 || j == 9999999 || j == 99999999 || j == (size - 1))
			{
				std::cout << "    read bytes: " << j+1 << " / " << size << "\n";
			}
		}

		std::cout << "\n";

		obj->hashBufferToCuckooFilter(flow_key_tmp, buffer, size);
		delete [] buffer;
	}
	ifs_flows.close();
    	obj->writeFingerprint();
	STOP  //digest stop

	record.open(experiment_record.c_str(), std::ios::app);
	std::cout << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record  << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record.close();

	delete obj;

	START  //query start
	//read from mrsh.sig
	//mrsh_CF* obj2 = new mrsh_CF(dir_size / BLOCK_SIZE / 2);
	mrsh_CF* obj2 = new mrsh_CF(memory_overhead);
	obj2->readFingerprint();

	printf("Read from \"%s\"\n\n", "mrsh.sig");

	int excerpt_num = 0;
	int excerpt_find = 0;
	int flow_match = 0;
	int false_positive = 0;
	/* modified 2024 01 13 */
	int false_positive_no_true_positive = 0;
	/* modified 2024 01 13 */
	int total_false_positive = 0;

	/* modified 2024 01 25 */
	double fp_per_query = 0;
	double fp_per_query_right = 0;
	double fp_per_query_right2 = 0;
	double fp_per_query_wrong = 0;
	double fp_flow_num = flow_num;
	/* modified 2024 01 25 */

	std::ifstream ifs_flows2(excerpt_data.c_str(), std::ios::in);
	ifs_flows2.seekg(0, std::ios::beg);

	while(std::getline(ifs_flows2, read_buffer))
	{
		excerpt_num += 1;
		std::stringstream word(read_buffer);
		std::string flow_key;
		int pos;
		std::string payload;

		word >> flow_key;
		word >> pos;
		word >> payload;

		char* flow_key_tmp = const_cast<char*>(flow_key.c_str());
		char* payload_tmp = const_cast<char*>(payload.c_str());

		int size = payload.length() / 2;
		unsigned char* buffer = new unsigned char[size];
		memset(buffer, 0, sizeof(unsigned char) * size);

		//std::cout << "Querying the excerpt from flow \"" << flow_key << "\", excerpt size: " << size << " bytes.\n";
		std::cout << "Query " << excerpt_num << ": querying the excerpt from flow \"" << flow_key << "\", excerpt size: " << size << " bytes.\n";

		for(j = 0; j < size; j++)
		{
			char ch[2];
			ch[0] = payload_tmp[j*2];
			ch[1] = payload_tmp[j*2+1];
			sscanf(ch, "%2hhx", &buffer[j]);
			if(j == 9999 || j == 99999 || j == 999999 || j == 9999999 || j == 99999999 || j == (size - 1))
			{
				std::cout << "---- read bytes: " << j+1 << " / " << size << "\n";
			}
		}

		unsigned int* results = obj2->bufferInCuckooFilter(buffer, size);
		if (results[2] >= MIN_RUN)
		{
			/* modified 2024 01 25 */
			double fp_per_query_tmp = total_false_positive;
			/* modified 2024 01 25 */

			excerpt_find += 1;
			printf("---- fine the excerpt: %i of %i (longest run: %i)\n", results[1], results[0], results[2]);

			bool fp = false;
			bool tp = false;
			for(i = 0; i < flow_num; i++)
			{

				unsigned int* results2 = obj2->bufferInCuckooFilter(flow_list[i].flow_key, buffer, size);

				if (results2[2] >= MIN_RUN)
				{
					if(strcmp(flow_list[i].flow_key, flow_key_tmp) == 0)
					{
						tp = true;
						printf("-------- match flow %s: %i of %i (longest run: %i)    true\n", flow_list[i].flow_key, results2[1], results2[0], results2[2]);
					}
					else
					{
						fp = true;
						total_false_positive += 1;
						printf("-------- match flow %s: %i of %i (longest run: %i)    false\n", flow_list[i].flow_key, results2[1], results2[0], results2[2]);
					}
				}
				/*else
				{
					printf("-------- flow %s is not match\n", flow_list[i].flow_key);
				}*/
				free(results2);
			}
			/* modified 2024 01 25 */
			if(tp)
			{
				flow_match += 1;
				fp_per_query_right = fp_per_query_right + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
			}
			if(fp)
			{
				/* modified 2024 01 13 */
				//false_positive += 1;
				if(tp)
				{
					false_positive += 1;
					fp_per_query_right2 = fp_per_query_right2 + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
				}
				else
				{
					false_positive_no_true_positive += 1;
					fp_per_query_wrong = fp_per_query_wrong + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
				}
				/* modified 2024 01 13 */
			}
			fp_per_query = fp_per_query + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
			/* modified 2024 01 25 */
		}

		std::cout << "\n";

		free(results);
		delete [] buffer;
	}
	ifs_flows2.close();
	STOP  //query stop

	/* modified 2024 01 25 */
	fp_per_query = fp_per_query / excerpt_num;
	if(flow_match == 0)
	{
		fp_per_query_right = 0;
	}
	else
	{
		fp_per_query_right = fp_per_query_right / flow_match;
	}
	if(false_positive == 0)
	{
		fp_per_query_right2 = 0;
	}
	else
	{
		fp_per_query_right2 = fp_per_query_right2 / false_positive;
	}
	if(false_positive_no_true_positive == 0)
	{
		fp_per_query_wrong = 0;
	}
	else
	{
		fp_per_query_wrong = fp_per_query_wrong / false_positive_no_true_positive;
	}
	/* modified 2024 01 25 */

	std::cout << "Total Query Time: " << TIME << " s = " << TIME / 60 << " min\n";
	std::cout << "Average Query Time: " << TIME / excerpt_num << " s = " << TIME / excerpt_num / 60 << " min\n";

	std::cout << "excerpt num: " << excerpt_num << "\n";
	std::cout << "excerpt find: " << excerpt_find << "    proportion: " << (double)excerpt_find * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	std::cout << "flow match: " << flow_match << "    proportion: " << (double)flow_match * 100 / excerpt_num << "%\n";
	std::cout << "false positive: " << false_positive << "    false positive rate: " << (double)false_positive * 100 / excerpt_num << "%\n";
	/* modified 2024 01 13 */
	std::cout << "false positive (no true positive): " << false_positive_no_true_positive << "    false positive rate (no true positive): " << (double)false_positive_no_true_positive * 100 / excerpt_num << "%\n";
	/* modified 2024 01 13 */
	/* modified 2024 01 25 */
	if(excerpt_find > 0)
	{
		std::cout << "total false positive: " << total_false_positive << "    average false positive: " << (double)total_false_positive / excerpt_find << " / excerpt\n";
	}
	else
	{
		std::cout << "total false positive: " << total_false_positive << "\n";
	}
	/* modified 2024 01 25 */
	std::cout << "Average false positive rate of queries: " << fp_per_query * 100 << "%\n";
	std::cout << "Average false positive rate of queries (right): " << fp_per_query_right * 100 << "%\n";
	std::cout << "Average false positive rate of queries (right2): " << fp_per_query_right2 * 100 << "%\n";
	std::cout << "Average false positive rate of queries (wrong): " << fp_per_query_wrong * 100 << "%\n";
	/* modified 2024 01 25 */

	record.open(experiment_record.c_str(), std::ios::app);

	record << "Total Query Time: " << TIME << " s = " << TIME / 60 << " min\n";
	record << "Average Query Time: " << TIME / excerpt_num << " s = " << TIME / excerpt_num / 60 << " min\n";

	record << "Experiment Results:" << "\n";
	record << "excerpt num: " << excerpt_num << "\n";
	record << "excerpt find: " << excerpt_find << "    proportion: " << (double)excerpt_find * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	record << "flow match: " << flow_match << "    proportion: " << (double)flow_match * 100 / excerpt_num << "%\n";
	record << "false positive: " << false_positive << "    false positive rate: " << (double)false_positive * 100 / excerpt_num << "%\n";
	/* modified 2024 01 13 */
	record << "false positive (no true positive): " << false_positive_no_true_positive << "    false positive rate (no true positive): " << (double)false_positive_no_true_positive * 100 / excerpt_num << "%\n";
	/* modified 2024 01 13 */
	/* modified 2024 01 25 */
	if(excerpt_find > 0)
	{
		record << "total false positive: " << total_false_positive << "    average false positive: " << (double)total_false_positive / excerpt_find << " / excerpt\n";
	}
	else
	{
		record << "total false positive: " << total_false_positive << "\n";
	}
	/* modified 2024 01 25 */
	record << "Average false positive rate of queries: " << fp_per_query * 100 << "%\n";
	record << "Average false positive rate of queries (right): " << fp_per_query_right * 100 << "%\n";
	record << "Average false positive rate of queries (right2): " << fp_per_query_right2 * 100 << "%\n";
	record<< "Average false positive rate of queries (wrong): " << fp_per_query_wrong * 100 << "%\n";
	/* modified 2024 01 25 */
	record << "\n\n\n\n\n";
	record.close();

	delete obj2;
}
