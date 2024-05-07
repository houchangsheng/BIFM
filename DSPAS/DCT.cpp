#include<iostream>
#include<fstream>
#include<cmath>
#include<cstring>
#include<random>
#include<string>
#include<sstream>

#include<bitset>

#include "hashutil.h"
#include "timing.h"
#include "LzmaUtil.h"

std::string experiment_record = "experiment_record.txt";

// 4GB TCP and UDP flows, 76% TCP flows, 24% UDP flows
// q  3 {4} 5
// K  
// L  256 {512 1024} 2048 4096
// evaluation metric: false positive rate    the number of falsely determined flows / the total number of distinct traffic flows
//                    false negative rate
//                    processing time

// extracted 10000 excerpts of different sizes (300, 400, 500, 600 bytes)
// all of them had appeared only once in the traffic

// evaluate wildcard queries and detection of similar strings:
// (1) use 300 byte excerpts, marked a different number of bytes of them as wildcard bytes (2~32 or 10~45 bytes)
// (2) the position of the wildcard bytes was randomly selected
// (3) for each wildcard excerpt, searched the traffic to ensure no other match exists for it except the original excerpt

// 2018 TIFS 100 GB digest 1 GB
//           1000 excerpts, 200 bytes
// 根据流量的实际情况设置索引表
// winnowing window: 64 bytes
// overlap length: 4 bytes
// DR = Raw traffic size / (Bloom filter size + Compressed index table size)
// evaluation metric:
//                    digesting time: the computation time of digesting the 100 GB traffic
//                    querying time: the computation time of querying for one excerpt

#define PI 3.14159265354
#define L 1024  // 1024
#define W 8 // 8
//#define q 4
#define q 6
#define K300 4.2 // 4.2  4.6
#define K400 4.6
#define K500 5.0
#define K600 5.2
#define LS_TH 7

long double DCT_Matrix[L][L];

long double DCT_trans;  //Avoiding overflow

int DCT_trans_tmp;

    long double max_dct = 0;
    long double min_dct = 0;
    long double max_idct = 0;
    long double min_idct = 0;


void InitDCTMatrix()
{
    int k, n;
    long double tmp = 0;
    for (k = 0; k < L; k++)
    {
        for (n = 0; n < L; n++)
        {
            tmp = PI * (2 * n + 1) * k / (2 * L);
            if (k == 0)
            {
                DCT_Matrix[k][n] = sqrt(1.0 / L) * cos(tmp);
            }
            else
            {
                DCT_Matrix[k][n] = sqrt(2.0 / L) * cos(tmp);
            }
        }
    }

    DCT_trans = 0;  //Avoiding overflow
    for (n = 0; n < L; n++)
    {
        DCT_trans += DCT_Matrix[0][n];
    }
    DCT_trans_tmp = ceil( log( ceil(DCT_trans) ) / log(2) );

    std::cout << "DCT_trans: " << DCT_trans << "    DCT_trans_tmp: " << DCT_trans_tmp << "\n\n";
}

//在流负载上滑动一个窗口，窗口大小W字节，窗口移动步长W字节，对窗口内字节进行哈希，输出W字节的字（word）
//即 {W字节} -> {W字节}，目的是使负载字符更加独立均匀的分布，符合高斯分布
void PreProcessing(char* byte_buffer, int* length)
{
    int i;
    int j = 0;

    //remove long strings of repetitive bytes
    char* new_buffer = new char[(*length)];
    memset(new_buffer, 0, sizeof(char) * (*length));
    int long_string = 0;
    int len = (*length);

    for(i = 0; i < (*length); i++)
    {
        new_buffer[j++] = byte_buffer[i];
        if( (i+1 < (*length)) && (byte_buffer[i] == byte_buffer[i+1]) )
        {
            long_string += 1;
        }
        else
        {
            if(long_string >= LS_TH)
            {
                //相同字符长串全部删除
                //j = j - long_string - 1;
                //len = len - long_string - 1;
                //相同字符长串保留一个字符
                j = j - long_string;
                len = len - long_string;
            }
            long_string = 0;
        }
    }

    //hash
    char* hash_window = new char[W];
    memset(hash_window, 0, sizeof(char) * W);
    int word_num = len / W;  //ignore the rest
    len = word_num * W;

    for(i = 0; i < word_num; i++)
    {
        memset(hash_window, 0, sizeof(char) * W);
        for(j = 0; j < W; j++)
        {
            hash_window[j] = new_buffer[i*W+j];
        }
        std::string tmp = HashUtil::SHA1Hash(hash_window, W);
        tmp.copy(&new_buffer[i*W], W, 0);
    }

    //后面的byte_buffer需要配合length来操作，此步骤是否是不必要的
    //memset(byte_buffer, 0, sizeof(char) * (*length));

    memcpy(byte_buffer, new_buffer, word_num * W);

    (*length) = len;

    //释放内存空间
    //free(new_buffer);
    //free(hash_window);
    delete [] new_buffer;
    delete [] hash_window;

    return;
}

//将W字节的字转换为int型数值
long long* BytesToInt(char* byte_buffer, int length)
{
    int i, j;
    int word_num = length / W;

    long long* x_origin = new long long[word_num];
    memset(x_origin, 0, sizeof(long long) * word_num);

    for(i = 0; i < word_num; i++)
    {
        long long tmp = 0;
        for (j = 0; j < W; j++)
        {
            if(j == 0)
            {
                tmp = (long long)byte_buffer[i * W + j];
            }
            else
            {
                //tmp = (tmp << 8) + ((long long)byte_buffer[i * W + j] & 0x0000000000000000ff);
                tmp = ((tmp << 8) | ((long long)byte_buffer[i * W + j] & 0x0000000000000000ff));
            }
        }
        x_origin[i] = tmp;
    }

    return x_origin;
}

//填充随机字符
char GenRandomChar()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    int value = dis(gen);

    char r = (char)(value & 0x000000ff);

    return r;
}

//DCT变换
long long* DCT(long long* x_origin, int length, int* length_after_dct)
{
    int i, j, k, n;

    int chunk_num = length / (L * W) + int( (length % (L * W)) != 0 );
    int chunk_rest = length % (L * W);

    long long* x_origin_tmp;

    if(chunk_rest != 0)
    {
        x_origin_tmp = new long long[chunk_num * L];
        memset(x_origin_tmp, 0, sizeof(long long) * chunk_num * L);
        memcpy(x_origin_tmp, x_origin, sizeof(long long) * length / W);

        for(i = 0; i < (L * W - chunk_rest) / W; i++)
        {
            long long tmp = 0;
            for(j = 0; j < W; j++)
            {
                if(j == 0)
                {
                    tmp = (long long)GenRandomChar();
                }
                else
                {
                    //tmp = (tmp << 8) + ((long long)GenRandomChar() & 0x0000000000000000ff);
                    tmp = ((tmp << 8) | ((long long)GenRandomChar() & 0x0000000000000000ff));
                }
            }
            x_origin_tmp[length / W + i] = tmp; 
        }
    }
    else
    {
        x_origin_tmp = new long long[chunk_num * L];
        memset(x_origin_tmp, 0, sizeof(long long) * chunk_num * L);
        memcpy(x_origin_tmp, x_origin, sizeof(long long) * length / W);
    }

    long double* x_dct_tmp = new long double[chunk_num * L];
    memset(x_dct_tmp, 0, sizeof(long double) * chunk_num * L);

    long long* x_dct = new long long[chunk_num * L];
    memset(x_dct, 0, sizeof(long long) * chunk_num * L);

    //long double max = 0;
    //long double min = 0;

    for (i = 0; i < chunk_num; i++)
    {
        for (k = 0; k < L; k++)
        {
            for (n = 0; n < L; n++)
            {
                x_dct_tmp[L * i + k] += (long double)(x_origin_tmp[L * i + n] * DCT_Matrix[k][n]);
            }

            if(max_dct < x_dct_tmp[L * i + k])
            {
                max_dct = x_dct_tmp[L * i + k];
            }
            if(min_dct > x_dct_tmp[L * i + k])
            {
                min_dct = x_dct_tmp[L * i + k];
            }

            //x_dct_tmp[L * i + k] = x_dct_tmp[L * i + k] / DCT_trans;  //Avoiding overflow
            //x_dct_tmp[L * i + k] = x_dct_tmp[L * i + k] >> DCT_trans_tmp;  //Avoiding overflow
            x_dct_tmp[L * i + k] = x_dct_tmp[L * i + k] / pow(2,DCT_trans_tmp);  //Avoiding overflow
            /*if(max < x_dct_tmp[L * i + k])
            {
                max = x_dct_tmp[L * i + k];
            }
            if(min > x_dct_tmp[L * i + k])
            {
                min = x_dct_tmp[L * i + k];
            }*/
            x_dct[L * i + k] = (long long)x_dct_tmp[L * i + k];
        }
    }
    (*length_after_dct) = chunk_num * L;

    //std::cout << "DCT Max = " << max << "  DCT Min = " << min << "\n\n";

    //释放内存空间
    delete [] x_origin_tmp;
    delete [] x_dct_tmp;

    return x_dct;
}

//量化
unsigned char* Quantization(long long* x_dct, int num)
{
    int i;

    //int q_tmp = ceil( log(DCT_trans)/log(2));
    //std::cout << "q: " << q << "    q_tmp: " << q_tmp << "    ";
    //q_tmp = q_tmp + q + 1;

    //int q_tmp = DCT_trans_tmp + q + 1;
    //int q_tmp = DCT_trans_tmp + q;
    int q_tmp = q + 1;
    //int q_tmp = q;

    long long mask = pow(2,64-q_tmp) - 1;
    //std::cout << "q_tmp: " << q_tmp << "    " << "Mask: 2^" << 64-q_tmp << " - 1\n";
    //std::cout << "Mask: " << mask << "\n\n";

    int num_tmp = num;

    unsigned char* dct_q = new unsigned char[4 + (num*q_tmp+7)/8];
    memset(dct_q, 0, sizeof(unsigned char) * (4 + (num*q_tmp+7)/8));

    dct_q[0] = (num & 0xff000000) >> 24;
    dct_q[1] = (num & 0x00ff0000) >> 16;
    dct_q[2] = (num & 0x0000ff00) >> 8;
    dct_q[3] = (num & 0x000000ff);

    int pos_char = 0;
    int pos_bit = 0;
    int rest = 0;

    for(i = 0; i < num; i++)
    {
        x_dct[i] = x_dct[i] / mask;

        pos_char = (i*q_tmp) / 8;
        pos_bit = (i*q_tmp) % 8;

        if(pos_bit + q_tmp >= 8)
        {
            rest = pos_bit + q_tmp - 8;

            dct_q[4+pos_char] = ( dct_q[4+pos_char] | ( ( x_dct[i] & (long long)(pow(2,q_tmp)-1) ) >> rest ) );
            dct_q[4+pos_char+1] = ( dct_q[4+pos_char+1] | ( ( x_dct[i] & (long long)(pow(2,rest)-1) ) << 8-rest ) );

        }
        else
        {
            dct_q[4+pos_char] = ( dct_q[4+pos_char] | ( ( x_dct[i] & (long long)(pow(2,q_tmp)-1) ) << (8 - pos_bit - q_tmp) ) );
        }
        x_dct[i] = x_dct[i] * mask;
    }

    return dct_q;
}

//压缩
unsigned char* EncRLE(unsigned char* dct_q, int* num)
{
    int i;

    //int q_tmp = DCT_trans_tmp + q + 1;
    //int q_tmp = DCT_trans_tmp + q;
    int q_tmp = q + 1;
    //int q_tmp = q;

    int num_tmp = ( ( (int)dct_q[0] << 24 ) | ( (int)dct_q[1] << 16 ) | ( (int)dct_q[2] << 8 ) | ( (int)dct_q[3] ) );

    num_tmp = 4 + (num_tmp * q_tmp + 7) / 8;

    std::ofstream ofs("EncTmp.sig", std::ios::trunc|std::ios::binary);
    for (i = 0; i < num_tmp; i++)
    {
        char ch = (char)dct_q[i];
        ofs.write((char*)&ch, 1);
    }
    ofs.close();

    std::ofstream ofs2("EncTmpLZMA.sig", std::ios::trunc|std::ios::binary);
    ofs2.close();


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

    WRes wres = InFile_Open(&inStream.file, "EncTmp.sig");
    if (wres != 0)
        PrintError_WRes("Cannot open input file", wres);

    wres = OutFile_Open(&outStream.file, "EncTmpLZMA.sig");
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


    std::ifstream ifs("EncTmpLZMA.sig", std::ios::binary);
    ifs.seekg(0, std::ios::end);
    (*num) = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    unsigned char* dct_enc = new unsigned char[(*num)];
    memset(dct_enc, 0, sizeof(unsigned char) * (*num));

    for (i = 0; i < (*num); i++)
    {
        char ch;
        ifs.read((char*)&ch, 1);
        dct_enc[i] = (unsigned char)ch;
    }
    ifs.close();

    return dct_enc;
}

//解压缩
unsigned char* DecRLE(unsigned char* dct_enc, int num)
{
    int i;

    std::ofstream ofs("EncTmpLZMA.sig", std::ios::trunc|std::ios::binary);
    for (i = 0; i < num; i++)
    {
        char ch = (char)dct_enc[i];
        ofs.write((char*)&ch, 1);
    }
    ofs.close();

    std::ofstream ofs2("EncTmp.sig", std::ios::trunc|std::ios::binary);
    ofs2.close();


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

    WRes wres = InFile_Open(&inStream.file, "EncTmpLZMA.sig");
    if (wres != 0)
        PrintError_WRes("Cannot open input file", wres);

    wres = OutFile_Open(&outStream.file, "EncTmp.sig");
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


    std::ifstream ifs("EncTmp.sig", std::ios::binary);
    ifs.seekg(0, std::ios::end);
    int num_tmp = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    unsigned char* dct_dec = new unsigned char[num_tmp];
    memset(dct_dec, 0, sizeof(unsigned char) * num_tmp);

    for (i = 0; i < num_tmp; i++)
    {
        char ch;
        ifs.read((char*)&ch, 1);
        dct_dec[i] = (unsigned char)ch;
    }
    ifs.close();

    return dct_dec;
}

//逆量化
long long* InvQuantization(unsigned char* dct_q, int* num)
{
    int i;

    //int q_tmp = ceil( log(DCT_trans)/log(2));
    //std::cout << "q: " << q << "    q_tmp: " << q_tmp << "    ";
    //q_tmp = q_tmp + q + 1;

    //int q_tmp = DCT_trans_tmp + q + 1;
    //int q_tmp = DCT_trans_tmp + q;
    int q_tmp = q + 1;
    //int q_tmp = q;

    long long mask = pow(2,64-q_tmp) - 1;
    //std::cout << "q_tmp: " << q_tmp << "    " << "Mask: 2^" << 64-q_tmp << " - 1\n";
    //std::cout << "Mask: " << mask << "\n\n";

    (*num) = ( ( (int)dct_q[0] << 24 ) | ( (int)dct_q[1] << 16 ) | ( (int)dct_q[2] << 8 ) | ( (int)dct_q[3] ) );

    long long* x_dct = new long long[(*num)];
    memset(x_dct, 0, sizeof(long long) * (*num) );

    int pos_char = 0;
    int pos_bit = 0;
    int rest = 0;

    for(i = 0; i < (*num); i++)
    {
        pos_char = (i*q_tmp) / 8;
        pos_bit = (i*q_tmp) % 8;

        if(pos_bit + q_tmp >= 8)
        {
            rest = pos_bit + q_tmp - 8;
            x_dct[i] = ( ( ( (long long)dct_q[4+pos_char] & (long long)(pow(2,8-pos_bit)-1) ) << rest ) | ( ( (long long)dct_q[4+pos_char+1] & (long long)(pow(2,8)-1) ) >> (8-rest) ) );
        }
        else
        {
            x_dct[i] = ( ( (long long)dct_q[4+pos_char] & (long long)(pow(2,8-pos_bit)-1) ) >> (8 - pos_bit - q_tmp) );
        }
        x_dct[i] = x_dct[i] * mask;
    }

    return x_dct;
}

//IDCT变换
long double* IDCT(long long* x_dct, int length)
{
    int i, k, n;
    //int chunk_num = length / (L * W) + int( (length % (L * W)) != 0 );
    int chunk_num = length / L + int( (length % L) != 0 );

    long double* x_idct = new long double[chunk_num * L];
    memset(x_idct, 0, sizeof(long double) * chunk_num * L);

    //long double max = 0;
    //long double min = 0;

    for (i = 0; i < chunk_num; i++)
    {
        for (n = 0; n < L; n++)
        {
            for (k = 0; k < L; k++)
            {
                x_idct[L * i + n] += (long double)x_dct[L * i + k] * DCT_Matrix[k][n];
            }

            if(max_idct < x_idct[L * i + n])
            {
                max_idct = x_idct[L * i + n];
            }
            if(min_idct > x_idct[L * i + n])
            {
                min_idct = x_idct[L * i + n];
            }

            //x_idct[L * i + n] = x_idct[L * i + n] * DCT_trans;  //Avoiding overflow
            //x_idct[L * i + n] = x_idct[L * i + n] << DCT_trans_tmp;  //Avoiding overflow
            x_idct[L * i + n] = x_idct[L * i + n] * pow(2,DCT_trans_tmp);  //Avoiding overflow
            /*if(max < x_idct[L * i + n])
            {
                max = x_idct[L * i + n];
            }
            if(min > x_idct[L * i + n])
            {
                min = x_idct[L * i + n];
            }*/
        }
    }
    //std::cout << "IDCT Max = " << max << "  IDCT Min = " << min << "\n\n";
    return x_idct;
}

//信号相关关系
bool CorrelationSignal(long long* x1, int len1, long long* x2, int len2, int K_TH)
{
    long double* Sig1 = new long double[len1];
    memset(Sig1, 0, sizeof(long double) * len1);

    long double* Sig2 = new long double[len2];
    memset(Sig2, 0, sizeof(long double) * len2);

    int i, j, k;

    for(i = 0; i < len1; i++)
    {
        Sig1[i] = (long double)x1[i];
    }
    for(i = 0; i < len2; i++)
    {
        Sig2[i] = (long double)x2[i];
    }

    bool flag = false;

    int chunk_num = len1 / L;
    int chunk_len = (L - len2 + 1);
    long double* CorSig = new long double[chunk_len * chunk_num];
    memset(CorSig, 0, sizeof(long double) * chunk_len * chunk_num);

    for(i = 0; i < chunk_num; i++)
    {
        long double mean = 0;
        for(j = 0; j < chunk_len; j++)
        {
            CorSig[i*chunk_len+j] = 0;
            for(k = 0; k < len2; k++)
            {
                CorSig[i*chunk_len+j] += Sig1[i*L+j+k] * Sig2[k];
            }
            mean += CorSig[i*chunk_len+j];
        }
        mean = mean / chunk_len;

        long double _STD = 0;
        for(j = 0; j < chunk_len; j++)
        {
            _STD += pow(CorSig[i*chunk_len+j]-mean,2);
        }
        _STD = sqrt(_STD / chunk_len);

        for(j = 0; j < chunk_len; j++)
        {
            if(CorSig[i*chunk_len+j] > _STD * K_TH)
            {
                //std::cout << "Chunk "<< i << ", Pos " << j << ": " << CorSig[i*chunk_len+j] << ", mean: " << mean << ", std: " << _STD << "\n";
                flag = true;
            }
        }

    }

    //释放内存空间
    //free(Sig1);
    //free(Sig2);
    //free(CorSig);
    delete [] Sig1;
    delete [] Sig2;
    delete [] CorSig;

    return flag;
}

//信号相关关系
bool CorrelationSignal(long double* x1, int len1, long long* x2, int len2, int K_TH)
{
    long double* Sig1 = new long double[len1];
    memset(Sig1, 0, sizeof(long double) * len1);

    long double* Sig2 = new long double[len2];
    memset(Sig2, 0, sizeof(long double) * len2);

    int i, j, k;

    for(i = 0; i < len1; i++)
    {
        Sig1[i] = (long double)x1[i];
    }
    for(i = 0; i < len2; i++)
    {
        Sig2[i] = (long double)x2[i];
    }

    bool flag = false;

    int chunk_num = len1 / L;
    int chunk_len = (L - len2 + 1);
    long double* CorSig = new long double[chunk_len * chunk_num];
    memset(CorSig, 0, sizeof(long double) * chunk_len * chunk_num);

    for(i = 0; i < chunk_num; i++)
    {
        long double mean = 0;
        for(j = 0; j < chunk_len; j++)
        {
            CorSig[i*chunk_len+j] = 0;
            for(k = 0; k < len2; k++)
            {
                CorSig[i*chunk_len+j] += Sig1[i*L+j+k] * Sig2[k];
            }
            mean += CorSig[i*chunk_len+j];
        }
        mean = mean / chunk_len;

        long double _STD = 0;
        for(j = 0; j < chunk_len; j++)
        {
            _STD += pow(CorSig[i*chunk_len+j]-mean,2);
        }
        _STD = sqrt(_STD / chunk_len);

        for(j = 0; j < chunk_len; j++)
        {
            if(CorSig[i*chunk_len+j] > _STD * K_TH)
            {
                //std::cout << "Chunk "<< i << ", Pos " << j << ": " << CorSig[i*chunk_len+j] << ", mean: " << mean << ", std: " << _STD << "\n";
                flag = true;
            }
        }

    }

    //释放内存空间
    //free(Sig1);
    //free(Sig2);
    //free(CorSig);
    delete [] Sig1;
    delete [] Sig2;
    delete [] CorSig;


    return flag;
}

void print_Buffer(std::string name, char* str, int length)
{
    int i;
    std::cout << name << ":\n";
    for (i = 0; i < length; i++)
    {
        std::cout << str[i];
    }
    std::cout << "\n";
}

void print_Matrix(std::string name, long long* str, int length)
{
    int i;
    int count = 0;
    std::cout << name << ":\n";
    for (i = 0; i < length / W; i++)
    {
        count += 1;
        std::cout << "\t";
        std::cout << str[i] << "  ";
        if(count == 10)
        {
            std::cout << "\n";
            count = 0;
        }
    }
    std::cout << "\n";
}

void print_Matrix(std::string name, long double* str, int length)
{
    int i;
    int count = 0;
    std::cout << name << ":\n";
    for (i = 0; i < length / W; i++)
    {
        count += 1;
        std::cout << "\t";
        std::cout << str[i] << "  ";
        if(count == 10)
        {
            std::cout << "\n";
            count = 0;
        }
    }
    std::cout << "\n";
}

void print_Distribution(long long* out, int len, bool flag)
{
    int i;
    if(flag)
    {
        int co_num_64[64];
        int co_num_64_2[64];
        memset(co_num_64, 0, sizeof(int)*64);
        memset(co_num_64_2, 0, sizeof(int)*64);
        for (i = 0; i < len / W; i++)
        {
            long long co_tmp = out[i];
            int count = 0;
            if(co_tmp < 0)
            {
                co_tmp = -co_tmp;
                while((co_tmp / 2 != 0) && count <= 63)
                {
                    co_tmp = co_tmp / 2;
                    count += 1;
                }
                co_num_64_2[count] += 1;
            }
            else
            {
                while((co_tmp / 2 != 0) && count <= 63)
                {
                    co_tmp = co_tmp / 2;
                    count += 1;
                }
                co_num_64[count] += 1;
            }
        }
        for(i = 63; i >= 0; i--)
        {
            std::cout << "-" << i << " : " << co_num_64_2[i] << "\n";
        }
        for(i = 0; i < 64; i++)
        {
            std::cout << i << " : " << co_num_64[i] << "\n";
        }
        std::cout << "\n";
    }
    else
    {
        int co_num_10[20];
        int co_num_10_2[20];
        memset(co_num_10, 0, sizeof(long long)*20);
        memset(co_num_10_2, 0, sizeof(long long)*20);
        for (i = 0; i < len / W; i++)
        {
            long long co_tmp = out[i];
            int count = 0;
            if(co_tmp < 0)
            {
                co_tmp = -co_tmp;
                while((co_tmp / 10 != 0) && count <= 19)
                {
                    co_tmp = co_tmp / 10;
                    count += 1;
                }
                co_num_10_2[count] += 1;
            }
            else
            {
                while((co_tmp / 10 != 0) && count <= 19)
                {
                    co_tmp = co_tmp / 10;
                    count += 1;
                }
                co_num_10[count] += 1;
            }
        }
        for(i = 19; i >= 0; i--)
        {
            std::cout << "-" << i << " : " << co_num_10_2[i] << "\n";
        }
        for(i = 0; i < 20; i++)
        {
            std::cout << i << " : " << co_num_10[i] << "\n";
        }
        std::cout << "\n";
    }
}

void digest(std::string flow_ID, char* buffer, int buffer_length)
{
    int i;
    int length = buffer_length;
    std::cout << "Read  " << length << "  bytes from flow \"" << flow_ID << "\", ";

    //预处理    和    字符转数值
    //在流负载上滑动一个窗口，窗口大小W字节，窗口移动步长W字节，对窗口内字节进行哈希，输出W字节的字（word）
    //即 {W字节} -> {W字节}，目的是使负载字符更加独立均匀的分布，符合高斯分布
    PreProcessing(buffer, &length);
    if(length == 0)
    {
        std::ofstream kkkk("kkkk.txt", std::ios::app|std::ios::binary);
        kkkk << flow_ID << "    buffer_length: " << buffer_length << "\n";
        kkkk.close();
        return;
    }
    //将W字节的字转换为int型数值
    long long* x_origin = BytesToInt(buffer, length);

    std::cout << "after preprocessing:  " << length << "  bytes." << "\n\n";

    //print_Matrix("Origin", x_origin, length);
    //std::cout << "x_origin distribution after PreProcessing and BytesToInt: \n";
    //print_Distribution(x_origin, length, 0);
    //print_Distribution(x_origin, length, 1);

    //DCT变换
    int dct_len;
    long long* x_dct = DCT(x_origin, length, &dct_len);

    /*std::cout << "origin chunk:  " << length / (L * W) << "    add chunk:  " << int( (length % (L * W)) != 0 ) << "    origin_len:  " << length / W << "    dct_len:  " << dct_len << "\n\n";
    print_Matrix("DCT", x_dct, dct_len);
    std::cout << "x_dct distribution before Quantization: \n";
    print_Distribution(x_dct, dct_len, 0);
    print_Distribution(x_dct, dct_len, 1);*/

    //量化
    unsigned char* dct_q = Quantization(x_dct, dct_len);

    //压缩存储
    int enc_len = 0;
    unsigned char* dct_enc = EncRLE(dct_q, &enc_len);

    int enc_len_hhx = enc_len * 2 + 1;
    char* dct_enc_hhx = new char[enc_len_hhx];
    memset(dct_enc_hhx, 0, sizeof(char) * enc_len_hhx);

    for(i = 0; i < enc_len; i++)
    {
        sprintf(&dct_enc_hhx[i*2], "%02hhx", (unsigned int)dct_enc[i]);
    }

    std::ofstream ofs_DCT_Enc("DCT_Enc.txt", std::ios::app|std::ios::binary);

    ofs_DCT_Enc << flow_ID << " ";

    //for (i = 0; i < enc_len_hhx; i++)
    for (i = 0; i < enc_len_hhx - 1; i++)
    {
        ofs_DCT_Enc.write((char*)&dct_enc_hhx[i], 1);
    }

    ofs_DCT_Enc << "\n";

    ofs_DCT_Enc.close();

    //释放内存空间
    //free(x_origin);
    //free(x_dct);
    //free(dct_q);
    //free(dct_enc);
    //free(dct_enc_hhx);
    delete [] x_origin;
    delete [] x_dct;
    delete [] dct_q;
    delete [] dct_enc;
    delete [] dct_enc_hhx;
}

long double* extract(unsigned char* dct_enc, int dec_len, int* idct_length)
{
    int i;

    unsigned char* dct_dec = DecRLE(dct_enc, dec_len);

    //逆量化
    int idct_len;
    long long* dct_iq = InvQuantization(dct_dec, &idct_len);

    //print_Matrix("Quantization DCT", x_dct, idct_len);
    //std::cout << "x_dct distribution after InvQuantization: \n";
    //print_Distribution(dct_iq, idct_len, 0);
    //print_Distribution(dct_iq, idct_len, 1);

    //IDCT变换
    long double* x_idct = IDCT(dct_iq, idct_len);

    (*idct_length) = idct_len;

    //print_Matrix("IDCT", x_idct, idct_len);

    //释放内存空间
    //free(dct_dec);
    //free(dct_iq);
    delete [] dct_dec;
    delete [] dct_iq;

    return x_idct;
}

struct flows
{
    std::string flow_ID;
    int bytes_num;
    char* buffer;
};

int main(int argc, char** argv)
{
	InitDCTMatrix();
	std::cout << "---------------------Config---------------------\n";
	std::cout << "L: " << L << "    W: " << W << "    q: " << q << "\n";
	std::cout << "K300: " << K300 << "    K400: " << K400 << "    K500: " << K500 << "    K600: " << K600 << "\n";
	std::cout << "------------------------------------------------\n\n";

	int i, j, k;

	std::string flow_data = "data_c.txt";
	if(argc >= 3)
	{
		flow_data = argv[1];
	}

	std::string excerpt_data = "excerpt_300_aa.txt";
	if(argc >= 3)
	{
		excerpt_data = argv[2];
	}


	std::ofstream record(experiment_record.c_str(), std::ios::app);

	time_t now = time(0);
	char* dt = ctime(&now);
	record << "Experiment Time: " << dt << "\n";

	std::cout << "Flow Data: " << flow_data << "\n";
	std::cout << "Excerpt Data: " << excerpt_data << "\n\n";

	record << "Flow Data: " << flow_data << "\n";
	record << "Excerpt Data: " << excerpt_data << "\n\n";

	record.close();


	START  //digest start
	//将数据包负载聚合为流负载
	int flow_num = 0;
	flows* total_flow = NULL;

	std::ifstream ifs_flows(flow_data.c_str(), std::ios::in);
	ifs_flows.seekg(0, std::ios::beg);

	std::string read_buffer;
	while(std::getline(ifs_flows, read_buffer))
	{
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

		bytes_num = bytes_num *  2;

		std::string flow_key = src + "-" + dst + "-" + proto;
		char* payload_tmp = const_cast<char*>(payload.c_str());
        
		bool match_flag = false;
		int flow_idx = flow_num;
		for(i = 0; i < flow_num; i++)
		{
			if(total_flow[i].flow_ID == flow_key)
			{
				match_flag = true;
				flow_idx = i;
				break;
			}
		}

		if(match_flag)
		{
			total_flow[flow_idx].buffer = (char*)realloc(total_flow[flow_idx].buffer, sizeof(char)*(total_flow[flow_idx].bytes_num+bytes_num+1));
			memcpy(total_flow[flow_idx].buffer + total_flow[flow_idx].bytes_num, payload_tmp, bytes_num);
			total_flow[flow_idx].bytes_num += bytes_num;
			total_flow[flow_idx].buffer[total_flow[flow_idx].bytes_num] = '\0';
		}
		else
		{
			total_flow = (flows*)realloc(total_flow, sizeof(flows)*(flow_num + 1));
			memset(total_flow + flow_num, 0, sizeof(flows));

			total_flow[flow_idx].buffer = (char*)malloc(sizeof(char)*(bytes_num+1));
			memcpy(total_flow[flow_idx].buffer, payload_tmp, bytes_num);
			total_flow[flow_idx].buffer[bytes_num] = '\0';
			total_flow[flow_idx].bytes_num = bytes_num;
			total_flow[flow_idx].flow_ID = flow_key;

			flow_num += 1;
		}
		//std::cout << "flow_num: " << flow_num << "    " << flow_key << "\n";
	}

	/*std::ofstream ofs_flows("data_flow.txt", std::ios::binary);
	for (i = 0; i < flow_num; i++)
	{
		ofs_flows << total_flow[i].flow_ID << " ";
		std::cout << total_flow[i].flow_ID << " ";
		//ofs_flows.write(total_flow[i].buffer, total_flow[i].bytes_num);
		ofs_flows << total_flow[i].buffer;
		std::cout << total_flow[i].buffer;
		ofs_flows << "\n";
		std::cout << "\n";
	}
	ofs_flows.close();*/

	ifs_flows.close();

	//读数据
	int length;
	char* buffer;

	std::string enc_data = "DCT_Enc.txt";
	std::ofstream ofs_DCT_Enc(enc_data.c_str(), std::ios::trunc|std::ios::binary);
	ofs_DCT_Enc.close();

	for (i = 0; i < flow_num; i++)
	//for (i = 0; i < 3; i++)
	{
		length = total_flow[i].bytes_num / 2;
		buffer = new char[length];
		memset(buffer, 0, sizeof(char) * length);
		std::cout << "Digest " << i + 1 << ": digest flow \"" << total_flow[i].flow_ID << "\", size: " << length << " bytes.\n";
		for(j = 0; j < length; j++)
		{
			char ch[2];
			ch[0] = total_flow[i].buffer[j*2];
			ch[1] = total_flow[i].buffer[j*2+1];
			sscanf(ch, "%2hhx", &buffer[j]);
			//sscanf(&total_flow[i].buffer[j*2], "%2hhx", &buffer[j]);
			if(j == 9999 || j == 99999 || j == 999999 || j == 9999999 || j == 99999999 || j == (length - 1))
			{
				std::cout << "    read bytes: " << j+1 << " / " << length << "\n";
			}
		}

		//print_Buffer("Text", buffer, length);

		digest(total_flow[i].flow_ID, buffer, length);

		//free(buffer);
		delete [] buffer;
	}
	STOP  //digest stop

	std::ifstream check_memory_overhead(enc_data.c_str(), std::ios::in);
	check_memory_overhead.seekg(0, std::ios::end);
	int memory_overhead = check_memory_overhead.tellg();
	check_memory_overhead.seekg(0, std::ios::beg);
	check_memory_overhead.close();

	record.open(experiment_record.c_str(), std::ios::app);

	std::cout << "Memory Overhead: " << memory_overhead << "\n";
	std::cout << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n";
	std::cout << "DCT Max = " << max_dct << "    DCT Min = " << min_dct << "\n\n";

	record << "Memory Overhead: " << memory_overhead << "\n";
	record << "Digest Time: " << TIME << " s = " << TIME / 60 << " min\n";
	record << "DCT Max = " << max_dct << "    DCT Min = " << min_dct << "\n\n";

	record.close();


	START  //query start
	//读片段
	int excerpt_num = 0;
	int excerpt_find = 0;
	int flow_match = 0;
	int false_negative = 0;
	int false_positive = 0;
	int non_fn_but_flase = 0;
	int total_false_positive = 0;

	/* modified 2024 01 25 */
	double fp_per_query = 0;
	double fp_per_query_right = 0;
	double fp_per_query_right2 = 0;
	double fp_per_query_wrong = 0;
	double fp_flow_num = flow_num;
	/* modified 2024 01 25 */

	int K_TH = K300;
	std::ifstream ifs_excerpts(excerpt_data.c_str(), std::ios::in);
	ifs_excerpts.seekg(0, std::ios::beg);

	std::string read_buffer_excerpt;
	while(std::getline(ifs_excerpts, read_buffer_excerpt))
	{
		/* modified 2024 01 25 */
		double fp_per_query_tmp = total_false_positive;
		/* modified 2024 01 25 */

		excerpt_num += 1;
		std::stringstream word(read_buffer_excerpt);
		std::string flow_key;
		int pos;
		std::string payload;

		word >> flow_key;
		word >> pos;
		word >> payload;

		//char* flow_key_tmp = const_cast<char*>(flow_key.c_str());
		char* payload_tmp = const_cast<char*>(payload.c_str());

		int size = payload.length() / 2;

		unsigned char* buffer2 = new unsigned char[size];
		memset(buffer2, 0, sizeof(unsigned char) * size);

		std::cout << "Query " << excerpt_num << ": querying the excerpt from flow \"" << flow_key << "\", excerpt size: " << size << " bytes.\n";
		for(j = 0; j < size; j++)
		{
			char ch[2];
			ch[0] = payload_tmp[j*2];
			ch[1] = payload_tmp[j*2+1];
			sscanf(ch, "%2hhx", &buffer2[j]);
			if(j == 9999 || j == 99999 || j == 999999 || j == 9999999 || j == 99999999 || j == (size - 1))
			{
				std::cout << "---- read bytes: " << j+1 << " / " << size << "\n";
			}
		}

		//读压缩数据
		std::ifstream ifs_DCT_Enc(enc_data.c_str(), std::ios::binary);
		ifs_DCT_Enc.seekg(0,std::ios::beg);

		int dec_len;
		unsigned char* dct_enc;
		int dec_len_hhx;
		char* dct_enc_hhx;
		int idct_len;
		long double* x_idct;

		bool positive = false;
		bool fp_flag = false;
		bool tp_flag = false;

		while(std::getline(ifs_DCT_Enc, read_buffer))
		{
			std::stringstream word(read_buffer);
			std::string flow_ID;
			std::string dct_enc_s;
			word >> flow_ID;
			word >> dct_enc_s;

			dec_len_hhx = dct_enc_s.length();
			dct_enc_hhx = new char[dec_len_hhx];
			memset(dct_enc_hhx, 0, sizeof(char) * dec_len_hhx);
			memcpy(dct_enc_hhx, dct_enc_s.c_str(), dec_len_hhx);

			dec_len = dec_len_hhx / 2;
			dct_enc = new unsigned char[dec_len];
			memset(dct_enc, 0, sizeof(unsigned char) * dec_len);
			for (j = 0; j < dec_len; j++)
			{
				char ch[2];
				ch[0] = dct_enc_hhx[j*2];
				ch[1] = dct_enc_hhx[j*2+1];
				sscanf(ch, "%2hhx", &dct_enc[j]);
			}

//std::cout << "flow_ID: " << flow_ID << "    dec_len_hhx: " << dec_len_hhx << "    dec_len: " << dec_len << "\n";///////////////////////////3333333333333333333333333333333333

			x_idct = extract(dct_enc, dec_len, &idct_len);

			//计算相关信号
			int length3;
			char* buffer3;

			bool print_flag = true;

			for(j = 0; j < W; j++)
			{
				length3 = size - j;
				buffer3 = new char[length3];
				memcpy(buffer3, buffer2 + j, sizeof(char) * length3);

				PreProcessing(buffer3, &length3);
				long long* x_origin3 = BytesToInt(buffer3, length3);
				//std::cout << "After preprocessing:  " << length3 << "  bytes, offset: " << j << "\n\n";

				int dct_len3 = length3 / W;
				//std::cout << "dct_len3:  " << dct_len3 << "\n\n";
				//std::cout << CorrelationSignal(x_idct, idct_len, x_origin3, dct_len3) << "\n\n";

				if(CorrelationSignal(x_idct, idct_len, x_origin3, dct_len3, K_TH))
				{
					positive = true;
					if(flow_key == flow_ID)
					{
						if(print_flag)
						{
							std::cout << "-------- match flow \"" << flow_ID << "\", true positive;\n";
							print_flag = false;
						}
						tp_flag = true;
					}
					else
					{
						if(print_flag)
						{
							std::cout << "-------- match flow \"" << flow_ID << "\", false positive;\n";
							print_flag = false;
							total_false_positive += 1;
						}
						fp_flag = true;
					}
				}
				//释放内存空间
				delete [] buffer3;
				delete [] x_origin3;
			}

			//释放内存空间
			delete [] dct_enc;
			delete [] dct_enc_hhx;
			delete [] x_idct;
		}
		ifs_DCT_Enc.close();

		/* modified 2024 01 25 */
		if(positive)
		{
			excerpt_find += 1;
			if(tp_flag)
			{
				flow_match += 1;
				fp_per_query_right = fp_per_query_right + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
				if(fp_flag)
				{
					std::cout << "---- contain error flow(s).\n\n";
					false_positive += 1;
					fp_per_query_right2 = fp_per_query_right2 + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
				}
				else
				{
					std::cout << "---- match the right flow.\n\n";
				}
			}
			else
			{
				if(fp_flag)
				{
					std::cout << "---- match only error flow(s).\n\n";
					non_fn_but_flase += 1;
					fp_per_query_wrong = fp_per_query_wrong + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
				}
			}
		}
		if(!positive)
		{
			std::cout << "---- don't match any flow.\n\n";
			false_negative += 1;
		}
		fp_per_query = fp_per_query + ((total_false_positive - fp_per_query_tmp) / fp_flow_num);
		/* modified 2024 01 25 */

		//释放内存空间
		delete [] buffer2;
	}
	ifs_excerpts.close();
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
	if(non_fn_but_flase == 0)
	{
		fp_per_query_wrong = 0;
	}
	else
	{
		fp_per_query_wrong = fp_per_query_wrong / non_fn_but_flase;
	}
	/* modified 2024 01 25 */

	std::cout << "Total Query Time: " << TIME << " s = " << TIME / 60 << " min\n";
	std::cout << "Average Query Time: " << TIME / excerpt_num << " s = " << TIME / excerpt_num / 60 << " min\n";

	std::cout << "IDCT Max = " << max_idct << "    IDCT Min = " << min_idct << "\n\n";

	std::cout << "excerpt num: " << excerpt_num << "\n";
	std::cout << "excerpt find: " << excerpt_find << "    proportion: " << (double)excerpt_find * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	std::cout << "flow match: " << flow_match << "    proportion: " << (double)flow_match * 100 / excerpt_num << "%\n";
	std::cout << "false positive: " << false_positive << "    false positive rate: " << (double)false_positive * 100 / excerpt_num << "%\n";
	std::cout << "false positive (don't have true positive): " << non_fn_but_flase << "    false positive rate (don't have true positive): " << (double)non_fn_but_flase * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	if(excerpt_find > 0)
	{
		std::cout << "total false positive: " << total_false_positive << "    average false positive: " << (double)total_false_positive / excerpt_find << " / excerpt\n";
	}
	else
	{
		std::cout << "total false positive: " << total_false_positive << "\n";
	}
	std::cout << "false negative: " << false_negative << "    false negative rate: " << (double)false_negative * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	std::cout << "Average false positive rate of queries: " << fp_per_query * 100 << "%\n";
	std::cout << "Average false positive rate of queries (right): " << fp_per_query_right * 100 << "%\n";
	std::cout << "Average false positive rate of queries (right2): " << fp_per_query_right2 * 100 << "%\n";
	std::cout << "Average false positive rate of queries (wrong): " << fp_per_query_wrong * 100 << "%\n";
	/* modified 2024 01 25 */

	record.open(experiment_record.c_str(), std::ios::app);

	record << "Total Query Time: " << TIME << " s = " << TIME / 60 << " min\n";
	record << "Average Query Time: " << TIME / excerpt_num << " s = " << TIME / excerpt_num / 60 << " min\n";

	record << "IDCT Max = " << max_idct << "    IDCT Min = " << min_idct << "\n";

	record << "Experiment Results:" << "\n";
	record << "excerpt num: " << excerpt_num << "\n";
	record << "excerpt find: " << excerpt_find << "    proportion: " << (double)excerpt_find * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	record << "flow match: " << flow_match << "    proportion: " << (double)flow_match * 100 / excerpt_num << "%\n";
	record << "false positive: " << false_positive << "    false positive rate: " << (double)false_positive * 100 / excerpt_num << "%\n";
	record << "false positive (don't have true positive): " << non_fn_but_flase << "    false positive rate (don't have true positive): " << (double)non_fn_but_flase * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	if(excerpt_find > 0)
	{
		record << "total false positive: " << total_false_positive << "    average false positive: " << (double)total_false_positive / excerpt_find << " / excerpt\n";
	}
	else
	{
		record << "total false positive: " << total_false_positive << "\n";
	}
	record << "false negative: " << false_negative << "    false negative rate: " << (double)false_negative * 100 / excerpt_num << "%\n";
	/* modified 2024 01 25 */
	record << "Average false positive rate of queries: " << fp_per_query * 100 << "%\n";
	record << "Average false positive rate of queries (right): " << fp_per_query_right * 100 << "%\n";
	record << "Average false positive rate of queries (right2): " << fp_per_query_right2 * 100 << "%\n";
	record<< "Average false positive rate of queries (wrong): " << fp_per_query_wrong * 100 << "%\n";
	/* modified 2024 01 25 */
	record << "\n\n\n\n\n";
	record.close();

	//释放内存空间
	for(i = 0; i < flow_num; i++)
	{
		free(total_flow[i].buffer);
	}
	free(total_flow);

	return 0;
}
