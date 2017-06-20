/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   test_ski_cache.c
 * Author: borchert
 *
 * Created on June 20, 2017, 9:27 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <srx/srxcryptoapi.h>
#include "client/srx_api.h"
#include "server/ski_cache.h"

typedef struct {
  u_int8_t     ski[SKI_LENGTH];
  u_int32_t    asn;
  u_int8_t     algoID;
  SRxUpdateID* updateID;
} TEST_SKI_DATA;


/**
 * Create the data object <SKI, AND, ALGO_ID [, UpdateID]>
 * @param asn
 * @param skiStr
 * @param algoID
 * @param updateID
 * @return 
 */
static TEST_SKI_DATA* createData(u_int32_t asn, char* skiStr, u_int8_t algoID, 
                                 SRxUpdateID* updateID)
{
  TEST_SKI_DATA* retVal = malloc (sizeof(TEST_SKI_DATA));  
  int idx, strIdx;
  int strLen = strlen(skiStr);
  char byteStr[] = { '0', 'x', '0', '0', '\0' };
  
  for (idx = 0, strIdx = 0; idx < SKI_LENGTH, strIdx < strLen; idx++, strIdx++)
  {
    byteStr[2] = skiStr[strIdx++];
    byteStr[3] = skiStr[strIdx];
    sscanf (byteStr, "%x", &retVal->ski[idx]);
  }
  
  retVal->asn      = asn;
  retVal->algoID   = algoID;
  if (updateID != NULL)
  {
    retVal->updateID = malloc(sizeof(SRxUpdateID));
    memcpy(retVal->updateID, updateID, sizeof(SRxUpdateID));
  }
  else
  {
    retVal->updateID = NULL;
  }
  
  return retVal;
}

/**
 * Release the allocated memory used for data
 * 
 * @param data The test data object 
 */
static void freeData(TEST_SKI_DATA* data)
{
  if (data->updateID != NULL)
  {
    free(data->updateID);
  }
  memset (data, sizeof(TEST_SKI_DATA), 0);
  free (data);
}

/**
 * Print the content of the data object on the screen
 * 
 * @param data The data object to be printed
 */
static void printData(TEST_SKI_DATA* data, char* prefix)
{
  int idx;
  u_int8_t* bNum = (u_int8_t*)data->ski;
  if (prefix == NULL)
  {
    prefix = "\0";
  }
  printf ("%sData: {ASN=%u; SKI='", prefix, data->asn);
  for (idx = 0; idx < SKI_LENGTH; idx++)
  {
    printf ("%02X", *bNum);
    bNum++;
  }
  printf("'; ALGOID=%u; UID=", data->algoID);
  if (data->updateID != NULL)
  {
    printf("%u}\n", *(data->updateID));
  }
  else
  {
    printf("N/A}\n");    
  }
}

/** 
 * This is the SKI Cache Callback handler. It will be called in case a 
 * validation for a particular update needs to be re-started
 * 
 * @param status The status of the update.
 * @param updateID pointer to the update id of the update that needs to be 
 *                 re-evaluated/
 */
void mySKI_CacheHandler(e_SKI_status status, SRxUpdateID* updateID)
{
  printf ("CALLBACK CALLED!\n");
}

/*
 * 
 */
int main(int argc, char** argv) 
{
  #define NO_ELEMENTS 12

  // Create Test Data
  TEST_SKI_DATA* testData[NO_ELEMENTS];
  memset (testData, sizeof(TEST_SKI_DATA*) * NO_ELEMENTS, 0); 
  testData[0]  = createData(65534, "AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154\0", 
                            1, NULL);
  testData[1]  = createData(65534, "47F23BF1AB2F8A9D26864EBBD8DF2711C74406EC\0",
                            2, NULL);
  testData[2]  = createData(65535, "3A7C104909B37C7177DF8F29C800C7C8E2B8101E\0",
                            3, NULL);
  testData[3]  = createData(65535, "8E232FCCAB9905C3D4802E27CC0576E6BFFDED64\0",
                            4, NULL);
  testData[4]  = createData(65536, "8BE8CA6579F8274AF28B7C8CF91AB8943AA8A260\0",
                            5, NULL);
  testData[5]  = createData(65536, "FB5AA52E519D8F49A3FB9D85D495226A3014F627\0",
                            6, NULL);
  testData[6]  = createData(65537, "FDFEE7854889F25BF6ECB88AFAF39CE0EBC41E08\0",
                            7, NULL);
  testData[7]  = createData(65537, "7BEE8A35FD78325932ADEF853A6B1F340C1F3DEF\0",
                            8, NULL);
  testData[8]  = createData(65538, "C38D869FF91E6307F1E0ABA99F3DA7D35A106E7F\0",
                            9, NULL);
  testData[9]  = createData(65538, "18494DAA1B2DFD80636AE943D9DC9FF42C1AF9D9\0",
                            10, NULL);
  testData[10] = createData(65539, "63729E346F7D10E3D037BCF365F9D19E074884E6\0",
                            11, NULL);
  testData[11] = createData(65539, "A85B22DB3471890155F66B78EB835E4F504D56F4\0",
                            12, NULL);
  
  int idx, elements=12;
  printf ("Test Data:\n");
  for (idx = 0; idx < elements; idx++)
  {
    printData(testData[idx], " -> ");
  }

  SKI_CACHE* cache = createSKICache(mySKI_CacheHandler);

  printf ("Register Data:\n");
  for (idx = 0; idx < elements; idx++)
  {
    printData(testData[idx], " Register ");
    //registerUpdateSKI(cache, SRxUpdateID* updateID, SCA_BGPSEC_SecurePath* bgpsec);    
    //unregisterUpdateSKI(cache, SRxUpdateID* updateID);
    
    registerKeySKI(cache, testData[idx]->ski, testData[idx]->algoID, 
                          testData[idx]->asn);
  }
  
  printf ("Register Data:\n");
  for (idx = 0; idx < elements; idx++)
  {
    printData(testData[idx], " Unregister ");
    //registerUpdateSKI(cache, SRxUpdateID* updateID, SCA_BGPSEC_SecurePath* bgpsec);    
    //unregisterUpdateSKI(cache, SRxUpdateID* updateID);    
    unregisterKeySKI(cache, testData[idx]->ski, testData[idx]->algoID, 
                            testData[idx]->asn);
  }
  
  printf ("Clean Cache:\n");  
  clean(cache);  
  
  printf ("Release Cache:\n");    
  releaseSKICache(cache);

  cache=NULL;
  
  // Clean up Test Data
  for (idx = 0; idx < elements; idx++)
  {
    freeData(testData[idx]);
    testData[idx]=NULL;
  }
  
  return (EXIT_SUCCESS);
}

