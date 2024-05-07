#ifndef _BITMAPTABLE_H_
#define _BITMAPTABLE_H_

#include <string.h>
#include <iostream>
#include "config.h"

class BitmapTable
{
	char flow_id[36];
	unsigned char* bitmap_row;
	size_t num;

	unsigned char* packet_cache;
	int pc_len;

public:

	BitmapTable(size_t bytes_num)
	{
		num = bytes_num;
		bitmap_row = new unsigned char[num];
		memset(bitmap_row, 0, sizeof(unsigned char) * num);

		packet_cache = new unsigned char[ROLLING_WINDOW+WINNOWING_WINDOW];
		memset(packet_cache, 0, sizeof(unsigned char) * (ROLLING_WINDOW+WINNOWING_WINDOW));
		pc_len = 0;
	}

	~BitmapTable()
	{
		delete bitmap_row;
		delete packet_cache;
	}

	void setFlowID(char* flow_id_tmp)
	{
		strcpy(flow_id, flow_id_tmp);
		flow_id[strlen(flow_id_tmp)] = '\0';
	}

	char* getFlowID()
	{
		return flow_id;
	}

	void setBitmapRow(int pos, unsigned char ch)
	{
		bitmap_row[pos] = ch;
	}

	unsigned char getBitmapRow(int pos)
	{
		return bitmap_row[pos];
	}

	size_t getNum()
	{
		return num;
	}

	void setBit(int idx)
	{
		int pos_char = idx / 8;
		int pos_bit = idx % 8;
		bitmap_row[pos_char] = bitmap_row[pos_char] | (1 << (7 - pos_bit));
	}

	/* modified 2023 10 26 */
	bool checkBit(int idx)
	{
		int pos_char = idx / 8;
		int pos_bit = idx % 8;
		if( (bitmap_row[pos_char] & (1 << (7 - pos_bit)) ) != 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	/* modified 2023 10 26 */

	bool compare(BitmapTable* bt_tmp)
	{
		for (int i = 0; i < num; i++)
		{
			//如果bt_tmp不被包含在此BitmapTable中，则返回false；
			if ((bt_tmp->getBitmapRow(i) & bitmap_row[i]) != bt_tmp->getBitmapRow(i))
			{
				return false;
			}
		}
		return true;
	}

	// fuzzy compare for block query (stage 2)
	bool fuzzy_compare(BitmapTable* bt_tmp, int threshold)
	{
		int count = 0;
		for (int i = 0; i < num; i++)
		{
			if ((bt_tmp->getBitmapRow(i) & bitmap_row[i]) != bt_tmp->getBitmapRow(i))
			{
				unsigned char uch = ( (bt_tmp->getBitmapRow(i) & bitmap_row[i]) ^ bt_tmp->getBitmapRow(i) );
				for(int j = 0; j < 8; j++)
				{
					count += ((uch >> j) & 0x1);
				}
				if(count >= threshold)
				{
					return false;
				}
			}
		}
		return true;
	}

	/* modified 2023 10 26 */
	int fuzzy_compare2(BitmapTable* bt_tmp, int threshold)
	{
		int count = 0;
		for (int i = 0; i < num; i++)
		{
			if ((bt_tmp->getBitmapRow(i) & bitmap_row[i]) != bt_tmp->getBitmapRow(i))
			{
				unsigned char uch = ( (bt_tmp->getBitmapRow(i) & bitmap_row[i]) ^ bt_tmp->getBitmapRow(i) );
				for(int j = 0; j < 8; j++)
				{
					count += ((uch >> j) & 0x1);
				}
				/* modified 2024 01 06 */
				if(count > threshold + 1)
				/* modified 2024 01 06 */
				{
					return count;
				}
			}
		}
		return count;
	}
	/* modified 2023 10 26 */

	// rank for flow query (stage 3)
	bool rank(BitmapTable* bt_tmp, double threshold)
	{
		int count = 0;
		int count_tmp = 0;
		for (int i = 0; i < num; i++)
		{
			if ((bt_tmp->getBitmapRow(i) & bitmap_row[i]) != bt_tmp->getBitmapRow(i))
			{
				return false;
			}
			else
			{
				unsigned char uch = bitmap_row[i];
				unsigned char uch_tmp = bt_tmp->getBitmapRow(i);
				for(int j = 0; j < 8; j++)
				{
					count += ((uch >> j) & 0x1);
					count_tmp += ((uch_tmp >> j) & 0x1);
				}
			}
		}

		if( ((double)count_tmp / count) < threshold)
		{
			return false;
		}

		return true;
	}

	void setPacketCache(unsigned char* payload, int payload_len)
	{
		//strncpy(packet_cache, payload, payload_len);
		memcpy(packet_cache, payload, sizeof(unsigned char) * payload_len);
		packet_cache[payload_len] = '\0';
		pc_len = payload_len;
	}

	/* modified 2023 10 27 */
	void addPacketCache(unsigned char* payload, int payload_len)
	{
		memcpy(packet_cache + pc_len, payload, sizeof(unsigned char) * payload_len);
		packet_cache[pc_len + payload_len] = '\0';
		pc_len = pc_len + payload_len;
	}
	/* modified 2023 10 27 */

	int getPacketCacheLen()
	{
		return pc_len;
	}

	unsigned char* getPacketCache()
	{
		return packet_cache;
	}

	bool compare2(BitmapTable* bt_tmp)
	{
		for (int i = 0; i < num; i++)
		{
			if (bt_tmp->getBitmapRow(i) != bt_tmp->getBitmapRow(i))
			{
				return false;
			}
		}
		return true;
	}

	bool isSameFlow(char* flow_id_tmp)
	{
		if (!strcmp(flow_id, flow_id_tmp))
		{
			return true;
		}
		return false;
	}

	bool compareAll(BitmapTable* bt_tmp)
	{
		if (getNum() != bt_tmp->getNum())
		{
			std::cout << "num diff!\n";
			return false;
		}
		else if (!isSameFlow(bt_tmp->getFlowID()))
		{
			std::cout << "flow diff!\n";
			return false;
		}
		else if (!compare2(bt_tmp))
		{
			std::cout << "bytes diff!\n";
			return false;
		}

		return true;
	}
};

#endif // #ifndef _BITMAPTABLE_H_
