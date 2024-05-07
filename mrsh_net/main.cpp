#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <limits.h>  /* PATH_MAX */

#include <unistd.h>
#include <dirent.h>

#include<iostream>
#include<fstream>
#include<cstring>
#include<string>
#include<sstream>

#include "timing.h"
#include "config.h"
#include "hashing.h"
#include "bloomfilter.h"

std::string experiment_record = "mrsh_net";

int BF_SIZE_IN_BYTES = 0;
int BLOCK_SIZE = 64;
int MIN_RUN = 2;

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
	BF_SIZE_IN_BYTES = lowerpower2(memory_overhead);
	initialize_settings();  //Bloom filter settings


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
	flows* flow_list = NULL;
	int flow_num = 0;

	//Generate Bloom Filter
	BLOOMFILTER* bf = init_empty_BF();

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

		//hashFileAndDo(flow_key_tmp, bf, buffer, 1, 0, size);

		unsigned int* results = hashFileAndDo(flow_key_tmp, bf, buffer, 1, 0, size);
		free(results);

		delete [] buffer;
	}
	ifs_flows.close();
	print_bf(bf);
	STOP  //digest stop

	record.open(experiment_record.c_str(), std::ios::app);
	std::cout << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record  << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record.close();

	destroy_bf(bf);

	START  //query start
	//read from myDB
	BLOOMFILTER* bf_read = init_empty_BF();

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

	readFileToBF("myDB", bf_read);
	printf("Read from \"%s\" - BLOCK_SIZE: %i, MIN_RUN: %i, MIN_ENTROPY: %.2f \n\n", "myDB", BLOCK_SIZE, MIN_RUN, MIN_ENTROPY);

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

		unsigned int* results = hashFileAndDo(bf_read, buffer, 2, 0, size);
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

				unsigned int* results2 = hashFileAndDo(flow_list[i].flow_key, bf_read, buffer, 2, 0, size);
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

	destroy_bf(bf_read);
}
