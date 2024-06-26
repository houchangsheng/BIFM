/* LzmaUtil.c -- Test application for LZMA compression
2023-03-07 : Igor Pavlov : Public domain */

#include "Precomp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CpuArch.h"

#include "Alloc.h"
#include "7zFile.h"
#include "LzFind.h"
#include "LzmaDec.h"
#include "LzmaEnc.h"

static const char * const kCantReadMessage = "Cannot read input file";
static const char * const kCantWriteMessage = "Cannot write output file";
static const char * const kCantAllocateMessage = "Cannot allocate memory";
static const char * const kDataErrorMessage = "Data error";

static void Print(const char *s)
{
  fputs(s, stdout);
}

static int PrintError(const char *message)
{
  Print("\nError: ");
  Print(message);
  Print("\n");
  return 1;
}

#define CONVERT_INT_TO_STR(charType, tempSize) \
  unsigned char temp[tempSize]; unsigned i = 0; \
  while (val >= 10) { temp[i++] = (unsigned char)('0' + (unsigned)(val % 10)); val /= 10; } \
  *s++ = (charType)('0' + (unsigned)val); \
  while (i != 0) { i--; *s++ = (charType)temp[i]; } \
  *s = 0; \
  return s;

static char * Convert_unsigned_To_str(unsigned val, char *s)
{
  CONVERT_INT_TO_STR(char, 32)
}

static void Print_unsigned(unsigned code)
{
  char str[32];
  Convert_unsigned_To_str(code, str);
  Print(str);
}

static int PrintError_WRes(const char *message, WRes wres)
{
  PrintError(message);
  Print("\nSystem error code: ");
  Print_unsigned((unsigned)wres);
  #ifndef _WIN32
  {
    const char *s = strerror(wres);
    if (s)
    {
      Print(" : ");
      Print(s);
    }
  }
  #endif
  Print("\n");
  return 1;
}

static int PrintErrorNumber(SRes val)
{
  Print("\n7-Zip error code: ");
  Print_unsigned((unsigned)val);
  Print("\n");
  return 1;
}

static int PrintUserError(void)
{
  return PrintError("Incorrect command");
}


#define IN_BUF_SIZE (1 << 16)
#define OUT_BUF_SIZE (1 << 16)


static SRes Decode2(CLzmaDec *state, ISeqOutStreamPtr outStream, ISeqInStreamPtr inStream,
    UInt64 unpackSize)
{
  const int thereIsSize = (unpackSize != (UInt64)(Int64)-1);
  Byte inBuf[IN_BUF_SIZE];
  Byte outBuf[OUT_BUF_SIZE];
  size_t inPos = 0, inSize = 0, outPos = 0;
  LzmaDec_Init(state);
  for (;;)
  {
    if (inPos == inSize)
    {
      inSize = IN_BUF_SIZE;
      RINOK(inStream->Read(inStream, inBuf, &inSize))
      inPos = 0;
    }
    {
      SRes res;
      SizeT inProcessed = inSize - inPos;
      SizeT outProcessed = OUT_BUF_SIZE - outPos;
      ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
      ELzmaStatus status;
      if (thereIsSize && outProcessed > unpackSize)
      {
        outProcessed = (SizeT)unpackSize;
        finishMode = LZMA_FINISH_END;
      }
      
      res = LzmaDec_DecodeToBuf(state, outBuf + outPos, &outProcessed,
        inBuf + inPos, &inProcessed, finishMode, &status);
      inPos += inProcessed;
      outPos += outProcessed;
      unpackSize -= outProcessed;
      
      if (outStream)
        if (outStream->Write(outStream, outBuf, outPos) != outPos)
          return SZ_ERROR_WRITE;
        
      outPos = 0;
      
      if (res != SZ_OK || (thereIsSize && unpackSize == 0))
        return res;
      
      if (inProcessed == 0 && outProcessed == 0)
      {
        if (thereIsSize || status != LZMA_STATUS_FINISHED_WITH_MARK)
          return SZ_ERROR_DATA;
        return res;
      }
    }
  }
}


static SRes Decode(ISeqOutStreamPtr outStream, ISeqInStreamPtr inStream)
{
  UInt64 unpackSize;
  int i;
  SRes res = 0;

  CLzmaDec state;

  /* header: 5 bytes of LZMA properties and 8 bytes of uncompressed size */
  unsigned char header[LZMA_PROPS_SIZE + 8];

  /* Read and parse header */

  {
    size_t size = sizeof(header);
    RINOK(SeqInStream_ReadMax(inStream, header, &size))
    if (size != sizeof(header))
      return SZ_ERROR_INPUT_EOF;
  }
  unpackSize = 0;
  for (i = 0; i < 8; i++)
    unpackSize += (UInt64)header[LZMA_PROPS_SIZE + i] << (i * 8);

  LzmaDec_CONSTRUCT(&state)
  RINOK(LzmaDec_Allocate(&state, header, LZMA_PROPS_SIZE, &g_Alloc))
  res = Decode2(&state, outStream, inStream, unpackSize);
  LzmaDec_Free(&state, &g_Alloc);
  return res;
}

static SRes Encode(ISeqOutStreamPtr outStream, ISeqInStreamPtr inStream, UInt64 fileSize)
{
  CLzmaEncHandle enc;
  SRes res;
  CLzmaEncProps props;

  enc = LzmaEnc_Create(&g_Alloc);
  if (enc == 0)
    return SZ_ERROR_MEM;

  LzmaEncProps_Init(&props);
  res = LzmaEnc_SetProps(enc, &props);

  if (res == SZ_OK)
  {
    Byte header[LZMA_PROPS_SIZE + 8];
    size_t headerSize = LZMA_PROPS_SIZE;
    int i;

    res = LzmaEnc_WriteProperties(enc, header, &headerSize);
    for (i = 0; i < 8; i++)
      header[headerSize++] = (Byte)(fileSize >> (8 * i));
    if (outStream->Write(outStream, header, headerSize) != headerSize)
      res = SZ_ERROR_WRITE;
    else
    {
      if (res == SZ_OK)
        res = LzmaEnc_Encode(enc, outStream, inStream, NULL, &g_Alloc, &g_Alloc);
    }
  }
  LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
  return res;
}
