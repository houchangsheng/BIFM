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

#include "BitmapTable.h"
#include "./lzma/LzmaUtil.h"

std::string experiment_record = "WBS_pc_bm2_loose";

int BF_SIZE_IN_BYTES = 0;
int filter_number = 2048;

int WINNOWING_WINDOW = 64;
int SHINGLING_BYTES = 4;
int DOWN_SAMPLING_TH = 40;

int block_threshold = 1;
int check_threshold = 1;

void writeFingerprint(BLOOMFILTER** bf, BitmapTable** bitmap_table, int flow_num)
{
	for (int i = 0; i < filter_number; i++)
	{
		print_bf(bf[i], i);
	}

	std::ofstream ofs("FlowName.sig", std::ios::binary);
	size_t i, j;

	if (flow_num > 0)
	{
		ofs << flow_num << "\n";
		ofs << bitmap_table[0]->getNum() << "\n";
		for (i = 0; i < flow_num; i++)
		{
			ofs << bitmap_table[i]->getFlowID() << "\n";
		}

		std::ofstream ofs_content("BitmapTable.sig", std::ios::binary);
		for (i = 0; i < flow_num; i++)
		{
			for (j = 0; j < bitmap_table[i]->getNum(); j++)
			{
				char ch = bitmap_table[i]->getBitmapRow(j);
				ofs_content.write((char*)&ch, 1);
			}
		}
		ofs_content.close();

		CFileSeqInStream inStream;
		CFileOutStream outStream;
		int res;

		LzFindPrepare();

		FileSeqInStream_CreateVTable(&inStream);
		File_Construct(&inStream.file);
		inStream.wres = 0;

		FileOutStream_CreateVTable(&outStream);
		File_Construct(&outStream.file);
		outStream.wres = 0;

		WRes wres = InFile_Open(&inStream.file, "BitmapTable.sig");
		if (wres != 0)
			PrintError_WRes("Cannot open input file", wres);

		wres = OutFile_Open(&outStream.file, "BitmapTableLZMA.sig");
		if (wres != 0)
			PrintError_WRes("Cannot open output file", wres);

		UInt64 fileSize;
		wres = File_GetLength(&inStream.file, &fileSize);
		if (wres != 0)
			PrintError_WRes("Cannot get file length", wres);
		res = Encode(&outStream.vt, &inStream.vt, fileSize);

		if (res != SZ_OK)
		{
			if (res == SZ_ERROR_MEM)
				PrintError(kCantAllocateMessage);
			else if (res == SZ_ERROR_DATA)
				PrintError(kDataErrorMessage);
			else if (res == SZ_ERROR_WRITE)
				PrintError_WRes(kCantWriteMessage, outStream.wres);
			else if (res == SZ_ERROR_READ)
				PrintError_WRes(kCantReadMessage, inStream.wres);
			PrintErrorNumber(res);
		}

		File_Close(&outStream.file);
		File_Close(&inStream.file);
	}
	ofs.close();
}

BitmapTable** readFingerprint(BLOOMFILTER** bf, BitmapTable** bitmap_table, int& flow_num)
{
	std::ifstream ifs("FlowName.sig", std::ios::binary);

	ifs.seekg(0, std::ios::beg);

	size_t i, j;

	ifs >> flow_num;
	int bytes_num;
	ifs >> bytes_num;

	if (bitmap_table == NULL)
	{
		bitmap_table = (BitmapTable**)malloc(flow_num * sizeof(BitmapTable*));
		for (i = 0; i < flow_num; i++)
		{
			std::string flow_identifier;
			ifs >> flow_identifier;
			bitmap_table[i] = new BitmapTable(bytes_num);
			bitmap_table[i]->setFlowID((char*)flow_identifier.c_str());
		}

		CFileSeqInStream inStream;
		CFileOutStream outStream;
		int res;

		LzFindPrepare();

		FileSeqInStream_CreateVTable(&inStream);
		File_Construct(&inStream.file);
		inStream.wres = 0;

		FileOutStream_CreateVTable(&outStream);
		File_Construct(&outStream.file);
		outStream.wres = 0;

		WRes wres = InFile_Open(&inStream.file, "BitmapTableLZMA.sig");
		if (wres != 0)
			PrintError_WRes("Cannot open input file", wres);

		wres = OutFile_Open(&outStream.file, "BitmapTable2.sig");
		if (wres != 0)
			PrintError_WRes("Cannot open output file", wres);

		res = Decode(&outStream.vt, &inStream.vt);

		if (res != SZ_OK)
		{
			if (res == SZ_ERROR_MEM)
				PrintError(kCantAllocateMessage);
			else if (res == SZ_ERROR_DATA)
				PrintError(kDataErrorMessage);
			else if (res == SZ_ERROR_WRITE)
				PrintError_WRes(kCantWriteMessage, outStream.wres);
			else if (res == SZ_ERROR_READ)
				PrintError_WRes(kCantReadMessage, inStream.wres);
			PrintErrorNumber(res);
		}

		File_Close(&outStream.file);
		File_Close(&inStream.file);

		std::ifstream ifs_content("BitmapTable2.sig", std::ios::binary);
		ifs.seekg(0, std::ios::beg);
		for (i = 0; i < flow_num; i++)
		{
			for (j = 0; j < bytes_num; j++)
			{
				char ch;
				ifs_content.read((char*)&ch, 1);
				bitmap_table[i]->setBitmapRow(j, ch);
			}
		}
		ifs_content.close();
	}
	ifs.close();

	for (int i = 0; i < filter_number; i++)
	{
		readFileToBF(bf[i], i);
	}
	return bitmap_table;
}

int main(int argc, char** argv)
{
	int i, j, k;
	std::uint64_t dir_size = 3568047512;
	std::uint64_t dataset_size = 3633820402;

	int data_reduction_ratio = 40;
	std::string flow_data = "data_c_aa.txt";
	std::string excerpt_data = "find_seg_500_aa.txt";
	if(argc >= 8)
	{
		filter_number = atoi(argv[1]);
		data_reduction_ratio = atoi(argv[2]);
		WINNOWING_WINDOW = atoi(argv[3]);
		SHINGLING_BYTES = atoi(argv[4]);
		DOWN_SAMPLING_TH = atoi(argv[5]);
		block_threshold = atof(argv[6]);
		check_threshold = atof(argv[7]);
		flow_data = argv[8];
		excerpt_data = argv[9];

		const char *d = "_";
		const char *d2 = ".";
		char *p;
		p = strtok(argv[9], d);
		p = strtok(NULL,d2);

		experiment_record = experiment_record + "_" + argv[3] + "_" + argv[4] + "_" + argv[5] + "_" + argv[7] + "_" + p + ".txt";
	}
	else
	{
		exit(1);
	}

	int memory_overhead = dataset_size / data_reduction_ratio;
	//BF_SIZE_IN_BYTES = lowerpower2(memory_overhead);
	BF_SIZE_IN_BYTES = lowerpower2(memory_overhead) / filter_number;
	initialize_settings();  //Bloom filter settings


	std::ofstream record(experiment_record.c_str(), std::ios::app);

	time_t now = time(0);
	char* dt = ctime(&now);
	record << "Experiment Time: " << dt << "\n";

	std::cout << "Filter Number: " << filter_number << "    Data Reduction Ratio: " << data_reduction_ratio << "\n\n";
	std::cout << "Flow Data: " << flow_data << "\n";
	std::cout << "Excerpt Data: " << excerpt_data << "\n\n";

	record << "Filter Number: " << filter_number << "    Data Reduction Ratio: " << data_reduction_ratio << "\n\n";
	record << "Flow Data: " << flow_data << "\n";
	record << "Excerpt Data: " << excerpt_data << "\n\n";

	record.close();


	START  //digest start
	//Generate Bloom Filter
	BLOOMFILTER** bf = new BLOOMFILTER*[filter_number];
	for(int i = 0; i < filter_number; i++)
	{
		bf[i] = init_empty_BF();
	}
	BitmapTable** bitmap_table = NULL;
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

		int size = bytes_num;
		unsigned char* buffer = new unsigned char[size];
		memset(buffer, 0, sizeof(unsigned char) * size);

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

		bitmap_table = hashBufferToBF(flow_key_tmp, bf, bitmap_table, flow_num, buffer, size);
		delete [] buffer;
	}
	ifs_flows.close();
    	writeFingerprint(bf, bitmap_table, flow_num);
	STOP  //digest stop

	record.open(experiment_record.c_str(), std::ios::app);
	std::cout << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record  << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n\n";
	record.close();

	for(int i = 0; i < filter_number; i++)
	{
		destroy_bf(bf[i]);
	}
	delete [] bf;
	if (bitmap_table != NULL)
	{
		for (int i = 0; i < flow_num; i++)
		{
			delete bitmap_table[i];
		}
		delete[] bitmap_table;
	}


	START  //query start
	BLOOMFILTER** bf_read = new BLOOMFILTER*[filter_number];
	for(int i = 0; i < filter_number; i++)
	{
		bf_read[i] = init_empty_BF();
	}
	BitmapTable** bitmap_table_read = NULL;
	int flow_num_read = 0;

	bitmap_table_read = readFingerprint(bf_read, bitmap_table_read, flow_num_read);
	printf("Read from \"%s\", \"%s\" and \"%s\"\n\n", "FlowName.sig", "BitmapTableLZMA.sig", "Filter.sig");

	int excerpt_num = 0;
	int excerpt_find = 0;
	int flow_match = 0;
	int false_positive = 0;
	/* modified 2023 10 26 */
	int false_positive_no_true_positive = 0;
	/* modified 2023 10 26 */
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

		unsigned int* results = checkBufferInBF(flow_key_tmp, bf_read, block_threshold, check_threshold, bitmap_table_read, flow_num_read, buffer, size);

		excerpt_find += results[0];
		flow_match += results[1];
		false_positive += results[2];
		/* modified 2023 10 26 */
		false_positive_no_true_positive += results[3];
		total_false_positive += results[4];
		/* modified 2023 10 26 */

		/* modified 2024 01 25 */
		fp_per_query = fp_per_query + (results[4] / fp_flow_num);
		if(results[1] == 1)
		{
			fp_per_query_right = fp_per_query_right + (results[4] / fp_flow_num);
		}
		if(results[2] == 1)
		{
			fp_per_query_right2 = fp_per_query_right2 + (results[4] / fp_flow_num);
		}
		if(results[3] == 1)
		{
			fp_per_query_wrong = fp_per_query_wrong + (results[4] / fp_flow_num);
		}
		/* modified 2024 01 25 */

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
	/* modified 2023 10 26 */
	std::cout << "false positive (no true positive): " << false_positive_no_true_positive << "    false positive rate (no true positive): " << (double)false_positive_no_true_positive * 100 / excerpt_num << "%\n";
	/* modified 2023 10 26 */
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
	/* modified 2023 10 26 */
	record << "false positive (no true positive): " << false_positive_no_true_positive << "    false positive rate (no true positive): " << (double)false_positive_no_true_positive * 100 / excerpt_num << "%\n";
	/* modified 2023 10 26 */
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

	for(int i = 0; i < filter_number; i++)
	{
		destroy_bf(bf_read[i]);
	}
	delete [] bf_read;
	if (bitmap_table_read != NULL)
	{
		for (int i = 0; i < flow_num; i++)
		{
			delete bitmap_table_read[i];
		}
		delete[] bitmap_table_read;
	}
}
