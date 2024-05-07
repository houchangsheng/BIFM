#ifndef _SINGLE_TABLE_H_
#define _SINGLE_TABLE_H_

#include <sstream>
#include <xmmintrin.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <fstream>

#include "printutil.h"
#include "bitsutil.h"

int Total_cks = 0;
int Alt_Index = 0;
int Index_Slot = 0;
int Index_notSlot = 0;
int No_Match = 0;

// the most naive table implementation: one huge bit array
template <size_t bits_per_tag>
class SingleTable
{
    static const size_t tags_per_bucket = 4;
    static const size_t bytes_per_bucket = (bits_per_tag * tags_per_bucket + 7) >> 3;

    //struct Bucket
    //{
    //    char bits_[bytes_per_bucket];
    //} __attribute__((__packed__));

    struct Bucket
    {
        char bits_[bytes_per_bucket];
    };

    // using a pointer adds one more indirection
    Bucket *buckets_;

public:
    static const uint32_t TAGMASK = (1ULL << bits_per_tag) - 1;
    size_t num_buckets;

    /*explicit SingleTable(size_t num)
    {
        num_buckets = num;
        buckets_ = new Bucket[num_buckets];
        CleanupTags();
    }*/

    explicit SingleTable(size_t memory_overhead)
    {
        num_buckets = memory_overhead / bytes_per_bucket;
        buckets_ = new Bucket[num_buckets];
        CleanupTags();
    }

    ~SingleTable()
    {
        delete[] buckets_;
    }

    void CleanupTags()
    {
        memset(buckets_, 0, bytes_per_bucket * num_buckets);
    }

    size_t SizeInBytes() const
    {
        return bytes_per_bucket * num_buckets;
    }

    size_t SizeInTags() const
    {
        return tags_per_bucket * num_buckets;
    }

    void CompareSingleTable(SingleTable* st)
    {
        /* for the given index in one table, check for the tags at the same index in the other table
            * match the tags, if one tag found, implies one chunk found
            * NAMING:
            * implicit table of this object is 1
            * table passed as param, is 2
            *
            * ASSUMPTION: comparing similar sized buckets only at present
            */
        size_t chunkCount = 0;
        size_t i, j, k;
        uint32_t tags1[tags_per_bucket];
        uint32_t tags2[tags_per_bucket];

        if (tags_per_bucket != 4)
        {
            std::cout << "Code works only when tags per bucket is 4" << std::endl;
        }

        Total_cks = 0;
        Alt_Index = 0;
        Index_Slot = 0;
        Index_notSlot = 0;
        No_Match = 0;

        // for each bucket, fetch the tags, and then compare them
        for (i = 0; i < num_buckets; i++)
        {
            chunkCount += matchBuckets(st, i);
        }
        std::cout << "Chunk matched: " << chunkCount << std::endl;
        std::cout << "Index_Slot: " << Index_Slot << "    Index_notSlot: " << Index_notSlot;
        std::cout << "    Alt_Index: " << Alt_Index << "    No_Match: " << No_Match << std::endl;
        std::cout << "Total Match: " << Index_Slot + Index_notSlot + Alt_Index;
        std::cout << "    Total_cks: " << Total_cks << std::endl;
    }

    /* match two buckets for a particular index. returns count of fingerprints matched at that bucket index */
    size_t matchBuckets(SingleTable* st, size_t index)
    {
        size_t i, j, k, fingerprintCount = 0;
        size_t matchCount = 0;
        uint32_t tags1[tags_per_bucket];
        uint32_t tags2[tags_per_bucket];
        
        /*--------------------------------hcs--------------------------------*/
        bool match_flag = false;
        /*--------------------------------hcs--------------------------------*/

        // fetch tags from that bucket
        for (j = 0; j < tags_per_bucket; j++)
        {
            tags1[j] = ReadTag(index, j);
            tags2[j] = st->ReadTag(index, j);
        }

        // compare the tags
        for (j = 0; j < tags_per_bucket; j++)
        {
            /*--------------------------------hcs--------------------------------*/
            match_flag = false;
            /*--------------------------------hcs--------------------------------*/
            if (tags1[j] != 0)
            {
                Total_cks++;
            }

            for (k = 0; k < tags_per_bucket; k++)
            {
                if (tags2[k] == 0)
                {
                    continue;
                }

                if (tags1[j] != 0)
                {
                    // if a tag is zero then dont compare
                    if (!(tags1[j] ^ tags2[k]))
                    {
                        fingerprintCount++;
                        /*--------------------------------hcs--------------------------------*/
                        match_flag = true;
                        /*--------------------------------hcs--------------------------------*/
                        if (j == k)
                        {
                            Index_Slot++;
                        }
                        else
                        {
                            Index_notSlot++;
                        }
                        continue;
                    }
                }
                else
                {
                    break; // break from inner loop
                }
            }

            /*--------------------------------hcs--------------------------------*/
            if (tags1[j] != 0 && match_flag == false)
            {
                size_t altIndex = index;
                altIndex = (altIndex ^ (tags1[j] * 0x5bd1e995)) % num_buckets;
                if (matchTagAtAlternateIndex(st, altIndex, tags1[j]) == 1)
                {
                    Alt_Index++;
                    fingerprintCount++;
                    match_flag = true;
                }
            }
            /*--------------------------------hcs--------------------------------*/

            if (tags1[j] != 0 && match_flag == false)
            {
                No_Match++;
            }
        }
        //std::cout << "Count:" << fingerprintCount << std::endl;
        return fingerprintCount;
    }

    size_t matchTagAtAlternateIndex(SingleTable* st, size_t index, size_t tag)
    {
        size_t j;
        uint32_t tags2[tags_per_bucket];

        //fetch tags from table 2 as we will be comparing table 1 tag at alternate index in table 2
        for (j = 0; j < tags_per_bucket; j++)
        {
            if (!(tag ^ st->ReadTag(index, j)))
            {
                return 1;
            }
        }
        
        return 0;
    }

    /* write the single table to file, as a fingerprint */
    void writeFingerprint(){
        std::ofstream ofs("mrsh.sig", std::ios::binary);
        size_t i,j;

        for (i=0;i<num_buckets;i++){
            for(j=0;j<bytes_per_bucket;j++){
                ofs.write((char*)&buckets_[i].bits_[j], 1);
            }
        }
    }

    /* read fingerprint  from 'mrsh.sig' file*/
    void readFingerprint(){
        std::ifstream ifs("mrsh.sig", std::ios::binary);

        ifs.seekg(0,std::ios::end);
        num_buckets = ((int)ifs.tellg() + (bytes_per_bucket - 1)) / bytes_per_bucket;
        ifs.seekg(0,std::ios::beg);

        //delete [] buckets_;
        buckets_ = new Bucket[num_buckets];
        CleanupTags();

        size_t i, j;
        for (i=0;i<num_buckets;i++){
            for(j=0;j<bytes_per_bucket;j++){
                ifs.read((char*)&buckets_[i].bits_[j], 1);
            }
        }
    }

    std::string Info() const  {
        std::stringstream ss;
        ss << "SingleHashtable with tag size: " << bits_per_tag << " bits \n";
        ss << "\t\tAssociativity: " << tags_per_bucket << "\n";
        ss << "\t\tTotal # of rows: " << num_buckets << "\n";
        ss << "\t\tTotal # slots: " << SizeInTags() << "\n";
        return ss.str();
    }

    // read tag from pos(i,j)
    // and check if tag_to_check already exists in the bucket. 
    inline uint32_t ReadTag(const size_t i, const size_t j) const
    {
        const char* p = buckets_[i].bits_;
        uint32_t tag;
        /* following code only works for little-endian */
        if (bits_per_tag == 2)
        {
            tag = *((uint8_t*)p) >> (j * 2);
        }
        else if (bits_per_tag == 4)
        {
            p += (j >> 1);
            tag = *((uint8_t*)p) >> ((j & 1) << 2);
        }
        else if (bits_per_tag == 8)
        {
            p += j;
            tag = *((uint8_t*)p);
        }
        else if (bits_per_tag == 12)
        {
            p += j + (j >> 1);
            tag = *((uint16_t*)p) >> ((j & 1) << 2);
        }
        else if (bits_per_tag == 16)
        {
            p += (j << 1);
            tag = *((uint16_t*)p);
        }
        else if (bits_per_tag == 32)
        {
            tag = ((uint32_t*)p)[j];
        }
        return tag & TAGMASK;
    }

    inline uint32_t ReadTag(const size_t i, const size_t j, const uint32_t tag_to_check) const {
        const char *p = buckets_[i].bits_;
        uint32_t tag;
        /* following code only works for little-endian */
        if (bits_per_tag == 2) {
            tag = *((uint8_t*) p) >> (j * 2);
        }
        else if (bits_per_tag == 4) {
            p += (j >> 1);
            tag = *((uint8_t*) p) >> ((j & 1) << 2);
        }
        else if (bits_per_tag == 8) {
            p += j;
            tag = *((uint8_t*) p);
        }
        else if (bits_per_tag == 12) {
            p += j + (j >> 1);
            tag = *((uint16_t*) p) >> ((j & 1) << 2);
        }
        else if (bits_per_tag == 16) {
            p += (j << 1);
            tag = *((uint16_t*) p);
        }
        else if (bits_per_tag == 32) {
            tag = ((uint32_t*) p)[j];
        }

        // if the tag already exists in the bucket. 
        if (!(tag^tag_to_check))
        {
            //std::cout<<"Existing Tag: " << tag << "\t New Tag: " << tag_to_check << std::endl;
            return -1; 
        }
        return tag & TAGMASK;
    }

    // write tag to pos(i,j)
    inline void  WriteTag(const size_t i, const size_t j, const uint32_t t) {
        char *p = buckets_[i].bits_;
        uint32_t tag = t & TAGMASK;
        /* following code only works for little-endian */
        if (bits_per_tag == 2) {
            *((uint8_t*) p) |= tag << (2*j);
        }
        else if (bits_per_tag == 4) {
            p += (j >> 1);
            if ( (j & 1) == 0) {
                *((uint8_t*) p)  &= 0xf0;
                *((uint8_t*) p)  |= tag;
            }
            else {
                *((uint8_t*) p)  &= 0x0f;
                *((uint8_t*) p)  |= (tag << 4);
            }
        }
        else if (bits_per_tag == 8) {
            ((uint8_t*) p)[j] =  tag;
        }
        else if (bits_per_tag == 12 ) {
            p += (j + (j >> 1));
            if ( (j & 1) == 0) {
                ((uint16_t*) p)[0] &= 0xf000;
                ((uint16_t*) p)[0] |= tag;
            }
            else {
                ((uint16_t*) p)[0] &= 0x000f;
                ((uint16_t*) p)[0] |= (tag << 4);
            }
        }
        else if (bits_per_tag == 16) {
            ((uint16_t*) p)[j] = tag;
        }
        else if (bits_per_tag == 32) {
            ((uint32_t*) p)[j] = tag;
        }

        return;
    }

    inline bool FindTagInBuckets(const size_t i1,
                                    const size_t i2,
                                    const uint32_t tag) const {
        const char* p1 = buckets_[i1].bits_;
        const char* p2 = buckets_[i2].bits_;

        uint64_t v1 =  *((uint64_t*) p1);
        uint64_t v2 =  *((uint64_t*) p2);

        // caution: unaligned access & assuming little endian
        if (bits_per_tag == 4 && tags_per_bucket == 4) {
            return hasvalue4(v1, tag) || hasvalue4(v2, tag);
        }
        else if (bits_per_tag == 8 && tags_per_bucket == 4) {
            return hasvalue8(v1, tag) || hasvalue8(v2, tag);
        }
        else if (bits_per_tag == 12 && tags_per_bucket == 4) {
            return hasvalue12(v1, tag) || hasvalue12(v2, tag);
        }
        else if (bits_per_tag == 16 && tags_per_bucket == 4) {
            return hasvalue16(v1, tag) || hasvalue16(v2, tag);
        }
        else {
            for (size_t j = 0; j < tags_per_bucket; j++ ){
                if ((ReadTag(i1, j) == tag) || (ReadTag(i2,j) == tag))
                    return true;
            }
            return false;
        }

    }

    inline bool  FindTagInBucket(const size_t i,  const uint32_t tag) const {
        // caution: unaligned access & assuming little endian
        if (bits_per_tag == 4 && tags_per_bucket == 4) {
            const char* p = buckets_[i].bits_;
            uint64_t v = *(uint64_t*)p; // uint16_t may suffice
            return hasvalue4(v, tag);
        }
        else if (bits_per_tag == 8 && tags_per_bucket == 4) {
            const char* p = buckets_[i].bits_;
            uint64_t v = *(uint64_t*)p; // uint32_t may suffice
            return hasvalue8(v, tag);
        }
        else if (bits_per_tag == 12 && tags_per_bucket == 4) {
            const char* p = buckets_[i].bits_;
            uint64_t v = *(uint64_t*)p;
            return hasvalue12(v, tag);
        }
        else if (bits_per_tag == 16 && tags_per_bucket == 4) {
            const char* p = buckets_[i].bits_;
            uint64_t v = *(uint64_t*)p;
            return hasvalue16(v, tag);
        }
        else {
            for (size_t j = 0; j < tags_per_bucket; j++ ){
                if (ReadTag(i, j) == tag) {
                    return true;
                }
            }
            return false;
        }
    }// FindTagInBucket

    inline  bool  DeleteTagFromBucket(const size_t i,  const uint32_t tag) {
        for (size_t j = 0; j < tags_per_bucket; j++ ){
            if (ReadTag(i, j) == tag) {
                assert (FindTagInBucket(i, tag) == true);
                WriteTag(i, j, 0);
                return true;
            }
        }
        return false;
    }// DeleteTagFromBucket

    inline  bool  InsertTagToBucket(const size_t i,  const uint32_t tag,
                                        const bool kickout, uint32_t& oldtag) {
        for (size_t j = 0; j < tags_per_bucket; j++ ){
            int32_t res;
            res = ReadTag(i, j, tag);
            //std::cout<< "read tag result: " << res << "\n";
            if (res == 0) { //Just checking if the bucket is empty, not for existing tags. 
                WriteTag(i, j, tag);
                return true;
            }
            else if (res == -1){
                //case when the tag already exists in the bucket. 
                return true;
            }
        }
        if (kickout) {
            size_t r = rand() % tags_per_bucket;
            oldtag = ReadTag(i, r);
            WriteTag(i, r, tag);
        }
        return false;
    }// InsertTagToBucket


    inline size_t NumTagsInBucket(const size_t i) {
        size_t num = 0;
        for (size_t j = 0; j < tags_per_bucket; j++ ){
            if (ReadTag(i, j) != 0) {
                num ++;
            }
        }
        return num;
    } // NumTagsInBucket

};// SingleTable

#endif // #ifndef _SINGLE_TABLE_H_
