/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 * 
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 * 
 * We would appreciate acknowledgment if the software is used.
 * 
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 * 
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 * 
 * The internal Cache structure is build along the AS number
 * 
 * The AS number is split into 2 word buckets.
 *             +--------+--------+--------+--------+
 * 4 Byte ASN  |      upper      |       AS2       |
 *             +--------+--------+--------+--------+
 * 
 * Most ASN's currently are in the AS2 bucket only 0x0000[0000] - 0x0000[FFFF]
 * The upper (left) bucket is relatively un-used. For each bit in the upper 
 * bucket, the cache reserves a 64K array for AS2. To keep the memory usage 
 * minimal but still have a speed access the upper uses a single linked list
 * and the AS2 portion a pointer array of 64K elements -> 256K/512K bytes 
 * depending on the pointer size (4 or 8 bytes)
 * 
 * The Cache list looks as follows:
 * 
 * [Cache]
 *   |
 * [upper]--->[upper]-->
 *   |      
 * +---+   
 * |AS2|---[AlgoID]--->[AlgoID]--->
 * +---+      |
 * |AS2|  [SKI;ASN;AlgoID]---[UID]--->[UID]--->
 * +---+      |>
 * .   .  [SKI;ASN;AlgoID]---[UID]--->[UID]--->
 * .   .      |>
 * +---+
 * |AS2|
 * +---+
 * 
 * Legend:
 * ===============================
 * 
 * Name           | Type   | Struct
 * -------------------------------------------------------------------------
 * Cache          | single | _SKI_CACHE
 * -------------------------------------------------------------------------
 * upper          | list   | _SKI_CACHE_NODE, _ski_cache_node (next)
 * -------------------------------------------------------------------------
 * AS2            | array  | _SKI_CACHE_ALGO_ID* [65535] with AS2 as index
 * -------------------------------------------------------------------------
 * AlgoID         | list   | _SKI_CACHE_ALGO_ID, _ski_cache_algo_id (next)
 * -------------------------------------------------------------------------
 * SKI;ASN;ALgoID | list   | _SKI_CACHE_DATA, _ski_cache_data (next)
 * -------------------------------------------------------------------------
 * UID            | list   | _SKI_CACHE_UPDATEID, _ski_cache_updateid (next)
 * -------------------------------------------------------------------------
 * 
 * 
 * +---+
 * |   |       Array (element)
 * +---+
 * 
 * ---  or |   Regular Pointer 
 * 
 * ---> or |>  Next Pointer
 * 
 * [    ]      Struct Element
 * 
 * @version 0.1.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.1.0.0 - 2017/06/19 - oborchert
 *            * modified function header for registering key ski's 
 *         - 2017/06/14 - oborchert
 *            * File created
 */
#include <stdlib.h>
#include <string.h>
#include <srx/srxcryptoapi.h>
#include "shared/srx_identifier.h"
#include "server/ski_cache.h"
#include "util/log.h"

/** The SKI center value. */
#define _SKI_AS2_ARRAY_SIZE 65536
/** At this point do NOT store the updateID as shared value. We keep a pointer 
 * to it. */
#define _SKI_UPD_SHARED false

/** This structure is a single linked list of update id's */
typedef struct _ski_cache_updateid
{
  /** Pointer to the next update id. */
  struct _ski_cache_updateid* next;
  /** Indicates if the uip instance is shared or not. If shared, the regular
   * call __freeUpdateData will NOT free the uid.
   */
  bool   shared;
  /** Pointer to the update id. */
  SRxUpdateID* updateID;  
} _SKI_CACHE_UPDATEID;

/** This struct represents a single ski cache data element. One for each triplet
 * <SKI/asn/algoid> */
typedef struct _ski_cache_data
{
  /** in case other ski's are stored as well */
  struct _ski_cache_data* next;
  /** number of keys received that use this particular ski and algo and asn 
   * combination (should be very rare). */
  u_int8_t    counter;
  /** The ASN of this cache data element */
  u_int32_t   asn;
  /** The SKI of this element */
  u_int8_t    ski[SKI_LENGTH];
  /** The algorithm ID */
  u_int8_t    algoID;
  /** List of updates assigned to this data element */
  _SKI_CACHE_UPDATEID* cacheUID;  
} _SKI_CACHE_DATA ;

/** This struct is a simple linked list for algorithm ID*/
typedef struct _ski_cache_algo_id {
  /** Next algorithm ID */
  struct _ski_cache_algo_id* next;
  /** The algorithm ID*/
  u_int8_t         algoID;  
  /** The ski cache data */
  _SKI_CACHE_DATA* cacheData;
} _SKI_CACHE_ALGO_ID;

/** The cache node if an ordered list of the first 2 bytes. It is expected to 
 * not have many elements. */
typedef struct _ski_cache_node {
  /** The next node. The value of next is larger than the value if this. */
  struct _ski_cache_node* next;  
  /** The left most 2 bytes of the AN number must match this node. */
  u_int16_t upper;
  /** */
  _SKI_CACHE_ALGO_ID* as2[_SKI_AS2_ARRAY_SIZE];
} _SKI_CACHE_NODE;

/** The internal SKI cache. */
typedef struct {
  /**
   * The parameter specifies a callback function with the following functionality:
   * Callback function to signal SKI changes. This function gets called by the
   * cache handler for each SKI modification that might impact the update status.
   * The receiver of this callback needs to determine if the update will be
   * re-validated. (most likely yes for SKI_NEW and SKI_REMOVED, ADD and DEL
   * should not affect the validation result (possible key roll over).
   * 
   * @param skiStatus one or more SKI's (keys) of the update changed.
   * @param updateID The update that is related to the SKI
   */
  void (*keyChange)(e_SKI_status skiStatus, SRxUpdateID* updateID);
  
  /** The SKI cache root node. */
  _SKI_CACHE_NODE* cacheNode;  
  /** The number of _SKI_CACHE_DATA elements stored. */
  int dataNodes;
} _SKI_CACHE;


////////////////////////////////////////////////////////////////////////////////
// Data Structure creation and Release
////////////////////////////////////////////////////////////////////////////////
static _SKI_CACHE_DATA* ___ski_freeCacheData(_SKI_CACHE_DATA* cData);

/**
 * Frees all memory allocated during creation of this element. It also will 
 * free the memory of uid if not shared!
 * 
 * @param cUID The cache Update data.
 * 
 * @return Value of the internal next pointer
 */
static _SKI_CACHE_UPDATEID* ___ski_freeCacheUID(_SKI_CACHE_UPDATEID* cUID)
{
  _SKI_CACHE_UPDATEID* next = NULL;
  if (cUID != NULL)
  {
    if (!cUID->shared && (cUID->updateID != NULL))
    {
      free(cUID->updateID);      
    }
    next = cUID->next;
    memset(cUID, sizeof(_SKI_CACHE_UPDATEID), 0);
    free (cUID);
  }  
  
  return next;          
}

/** This structure is used to parse the update. */
typedef struct {
  /** The number of segments. */
  u_int16_t   nrSegments;
  /** Number of signature blocks. */
  u_int16_t   nrSigBlocks;
  /** An array of as numbers (size if number of segments */
  u_int32_t** asn;
  /** This array contains the algorithm ids.*/
  u_int8_t algoID[2];
  /** An array of SKIs (array size is nrSigBlocks * nrSegments) */
  u_int8_t* ski[SKI_LENGTH];
} _SKI_INTERN_UPD_INFO;

/**
 * Create a new Update Data list element. The uid will be copied if the 
 * parameter shared is set to false.
 * 
 * @param updateID The SRx update id to be stored. It will store a copy of it if 
 *        shared = false.
 * @param shared if set to true, the given pointer will be linked,
 *               otherwise a copy of the given uid will be generated.
 * 
 * @return The update data or NULL if uid is NULL
 */
static _SKI_CACHE_UPDATEID* ___ski_createCacheUID(SRxUpdateID* updateID, 
                                                  bool shared)
{
  _SKI_CACHE_UPDATEID* cUID = NULL;
  if (updateID != NULL)
  {
    malloc(sizeof(_SKI_CACHE_UPDATEID));
    memset(cUID, sizeof(_SKI_CACHE_UPDATEID), 0);
    cUID->shared = shared;
    if (!cUID->shared)
    {
      cUID->updateID = malloc(sizeof(SRxUpdateID)); 
      memcpy (cUID->updateID, updateID, sizeof(SRxUpdateID));
    }
    else
    {
      cUID->updateID = updateID;
    }       
  }
  
  return cUID;          
}

/**
 * Free all memory allocated with the algorithmID. This includes the complete
 * data tree. This function returns the next algorithmID is it exists.
 * 
 * @param cAlgoID The algorithm ID tree to be removed.
 * 
 * @return The value of the next pointer
 */
static _SKI_CACHE_ALGO_ID* ___ski_freeCacheAlgoID(_SKI_CACHE_ALGO_ID* cAlgoID)
{
  _SKI_CACHE_ALGO_ID* next = NULL;
  if (cAlgoID != NULL)
  {
    next = cAlgoID->next;
    while (cAlgoID->cacheData != NULL)
    {
      cAlgoID->cacheData = ___ski_freeCacheData(cAlgoID->cacheData);
    }
    
    memset (cAlgoID, sizeof(_SKI_CACHE_ALGO_ID), 0);
    free (cAlgoID);
  }
  return next;
}


/**
 * Create a cache algorithm id list
 * 
 * @param algoID the algorithm identifier of the data node
 *
 * @return the algorithm ID
 */
static _SKI_CACHE_ALGO_ID* ___ski_createCacheAlgoID(u_int8_t algoID)
{
  _SKI_CACHE_ALGO_ID* cAlgoID = malloc(sizeof(_SKI_CACHE_ALGO_ID));
  
  memset (cAlgoID, sizeof(_SKI_CACHE_ALGO_ID), 0);  
  cAlgoID->algoID = algoID;
  
  return cAlgoID;
}

/**
 * Free this given cache data object including all assigned update id's
 * 
 * @param data The cache data to be removed
 * 
 * @return The value of the next pointer.
 */
static _SKI_CACHE_DATA* ___ski_freeCacheData(_SKI_CACHE_DATA* cData)
{
  _SKI_CACHE_DATA* next = NULL;
  
  if (cData != NULL)
  {
    // Store the next pointer
    next = cData->next;
    // Remove all update ids.
    while (cData->cacheUID != NULL)
    {
      cData->cacheUID = ___ski_freeCacheUID(cData->cacheUID);
    }
    memset (cData, sizeof(_SKI_CACHE_DATA), 0);
    free (cData);
  }
  
  return next;
}

/**
 * Create a cache dataNode
 * 
 * @param asn the ASN of the datanode
 * @param ski the ski of the data node
 * @param algoID the algorithm identifier of the data node
 * @param updateID The update identifier (can be NULL)
 * @param shared Indicates if the updateID is shared or not.
 *
 * @return the SKI cache data
 */
static _SKI_CACHE_DATA* ___ski_createCacheData(u_int32_t asn, 
                                             u_int8_t* ski, u_int8_t algoID, 
                                             SRxUpdateID* updateID, bool shared)
{
  _SKI_CACHE_DATA* cData = malloc(sizeof(_SKI_CACHE_DATA));
  memset (cData, sizeof(_SKI_CACHE_DATA), 0);
  
  cData->asn    = asn;
  cData->algoID = algoID;
  memcpy(cData->ski, ski, SKI_LENGTH);
  if (updateID != NULL)
  {
    cData->cacheUID = ___ski_createCacheUID(updateID, shared);
  }
   
  return cData;
}

/**
 * Free the memory allocated with this cache node and its underlying data 
 * structure. This function returns the value of the next pointer.
 * This function is very expensive.
 * 
 * @param cNode The cache node to be removed/
 * 
 * @return the next pointer
 */
static _SKI_CACHE_NODE* ___ski_freeCacheNode(_SKI_CACHE_NODE* cNode)
{
  _SKI_CACHE_NODE* next = NULL;
  
  if (cNode != NULL)
  {
    next = cNode->next;
    int idx = 0;
    for (idx = 0; idx < _SKI_AS2_ARRAY_SIZE; idx ++)
    {
      while (cNode->as2[idx] != NULL)
      {
        cNode->as2[idx] = ___ski_freeCacheAlgoID(cNode->as2[idx]);
      }
    }
  }
  
  return next;
}

/**
 * Generate a new cache node.
 * 
 * @param upper the upper value of the ASN if the cache node
 * 
 * @return The cache node.
 */
static _SKI_CACHE_NODE* ___ski_createCacheNode(u_int16_t upper)
{
  _SKI_CACHE_NODE* cNode = malloc(sizeof(_SKI_CACHE_NODE));
  
  memset (cNode, sizeof(_SKI_CACHE_NODE), 0);
  cNode->upper = upper;
  
  return cNode;
}

////////////////////////////////////////////////////////////////////////////////
// Data Retrival and Data Storing
////////////////////////////////////////////////////////////////////////////////

/**
 * Return the correct Cache Node or NULL if none is found. If create is set to 
 * true then a new one is created if none exists.
 * 
 * @param cache The cache where the cache node is located in 
 * @param upper The upper two bytes of the as number.
 * @param create If true create a new one if it does not exist.
 * 
 * @return The cache node or NULL if none is found.
 */
static _SKI_CACHE_NODE* __ski_getCacheNode(_SKI_CACHE* cache, u_int16_t upper, 
                                           bool create)
{
  /** The cache node. */
  _SKI_CACHE_NODE* cNode = NULL;
  _SKI_CACHE_NODE* prev = NULL;
  bool found = false;
  
  if (cache != NULL)
  { 
    if (cache->cacheNode != NULL)
    {
      cNode = cache->cacheNode;
    }
    else if (create)
    {
      cache->cacheNode = ___ski_createCacheNode(upper);
      cNode            = cache->cacheNode;
      found            = true;
    }
    
    while (!found && (cNode != NULL))
    {      
      if (upper < cNode->upper)
      {
        // OK we need to insert a new node
        if (create)
        {
          cNode = ___ski_createCacheNode(upper);
          if (prev != NULL)
          {
            cNode->next = prev->next;            
            prev->next  = cNode;
          }
          else
          {
            cNode->next      = cache->cacheNode;
            cache->cacheNode = cNode;
          }
          found = true;
        }
        else
        {
          cNode = NULL;
        }
        continue;
      }
      if (upper == cNode->upper)
      {
        found = true;
        continue;
      }
      prev = cNode;
      cNode = prev->next;
    }    
  }
  
  if (!found)
  {
    // cNode should be NULL if not found, so this line is not really necessary
    // but left it just in case.
    cNode = NULL;
  }
  
  return cNode;
}

/**
 * Add the given update udentifier to the cache data object
 * 
 * @param cacheData The cache data object
 * @param updateID the update identifier
 * @param shared specifies if this identifier is shared.
 */
static void __ski_addUpdateCacheUID(_SKI_CACHE_DATA* cacheData, 
                                    SRxUpdateID* updateID, bool shared)
{
  _SKI_CACHE_UPDATEID* cUID = NULL;
  _SKI_CACHE_UPDATEID* prev = NULL;
  bool added = false;
  int cmp = 0;

  if (cacheData != NULL)
  {
    if (cacheData->cacheUID == NULL)
    {
      cacheData->cacheUID = ___ski_createCacheUID(updateID, shared);
      added = true;
    }    
    cUID = cacheData->cacheUID;
    // Compare only the path validation section.
    while (!added)
    {
      cmp = (cUID != NULL) 
            ? compareSrxUpdateID(updateID, cUID->updateID, SRX_UID_PV) 
            : -1;
      if (cmp != 0)
      {
        if (cmp < 0)
        {
          // we need to insert the update ID
          cUID = ___ski_createCacheUID(updateID, shared);
          if (prev != NULL)
          {
            // Insert before this one
            cUID->next = prev->next;
            prev->next = cUID;
          }
          else
          {
            cUID->next = cacheData->cacheUID;
            cacheData->cacheUID = cUID;
          }
          added = true;
        }
        else
        {
          prev = cUID;
          cUID = cUID->next;          
        }
        cmp = 0;
      }
      else
      {
        // already added
        added = true;  
      }
      cmp = compareSrxUpdateID(updateID, cUID->updateID, SRX_UID_PV);
    }
  }
}

/**
 * Find the algorithm id for te given cache node. If create is set to true and
 * no algorithm identifier exists this function will create a new one.
 * 
 * @param cacheNode the cache node the algorithm identifier belongs too.
 * @param as2 the lower 2 bytes of the asn (old AS2 value).
 * @param algoID the algorithm identifier
 * @param create if true a new one will be generated if none exists.
 * 
 * @return The algorithm identifier or NULL is none is found.
 */
static _SKI_CACHE_ALGO_ID* __ski_getCacheAlgoID(_SKI_CACHE_NODE* cacheNode, 
                                                 u_int16_t as2, u_int8_t algoID, 
                                                 bool create)
{
  /** The Cache algorithm identifier */
  _SKI_CACHE_ALGO_ID* cAlgoID = NULL;
  _SKI_CACHE_ALGO_ID* prev;
  bool found = false;
  
  if (cacheNode != NULL)
  {
    if (cacheNode->as2[as2] != NULL)
    {
      cAlgoID = cacheNode->as2[as2];
    }
    else if (create)
    {
      cacheNode->as2[as2] = ___ski_createCacheAlgoID(algoID);
      found = true;
      cAlgoID = cacheNode->as2[as2];
    }            
    
    // Now we found an algorithm ID bin, go to the correct one.
    while (!found && (cAlgoID != NULL))
    {
      // Most likely the first one is the correct one - especially now where we 
      // only have one official algorithm identifier.
      if (cAlgoID->algoID == algoID)
      {
        found = true;
        continue;
      }
      if (algoID < cAlgoID->algoID)
      {
        // Ok we need to insert one.
        if (create)
        {
          cAlgoID = ___ski_createCacheAlgoID(algoID);
          if (prev != NULL)
          {
            cAlgoID->next = prev->next;
            prev->next    = cAlgoID;
          }
          else
          {
            cAlgoID->next       = cacheNode->as2[as2]->next;
            cacheNode->as2[as2] = cAlgoID;
          }
          found = true;
        }
        else
        {
          cAlgoID = NULL;
        }
        continue;
      }
      prev    = cAlgoID;
      cAlgoID = cAlgoID->next;
    }    
  }
  
  if (!found)
  {
    cAlgoID = NULL;
  }
          
  return cAlgoID;
}

/**
 * Return the cache data that matches this given <asn,ski,algoid> triplet.
 * This function also generated a cache data element if it does not exist.
 * 
 * @param cache The cache where to look in.
 * @param asn The ASN of the cache object
 * @param ski The SKI of the cache object
 * @param algoID The algorithm identifier of the cache object
 * @param uid The SRx UpdateID (can be NULL)
 * @param create if true the object will be created if it does not exist 
 *        already.
 * 
 * @return the cache data object or NULL.
 */
static _SKI_CACHE_DATA* _getCacheData(_SKI_CACHE* cache, u_int32_t asn,
                                      char* ski, u_int8_t algoID, bool create)
{
  /** The left most 2 bytes as unsigned word value. */
  u_int16_t upper = asn >> 16;
  /** The right most 2 bytes as unsigned word value (former AS2 number). */
  u_int16_t as2  = asn & 0xFFFF;
  
  _SKI_CACHE_NODE*    cNode   = NULL;
  _SKI_CACHE_ALGO_ID* cAlgoID = NULL;
  _SKI_CACHE_DATA*    cData   = NULL;
  _SKI_CACHE_DATA*    prev = NULL;
  bool found = false;
  int  cmp   = 0;
  
  // Get the cache Node
  if (cache != NULL)
  {
    // Retrieve the correct CacheNode from the cache. If the node does not exist
    // yet and create is false, the cacheNODE will be NULL
    cNode = __ski_getCacheNode(cache, upper, create);
                                         
    if (cNode != NULL)
    {
      // Retrieve the correct algoID list head from the cache. If the node does 
      // not exist yet and create is false, the cacheAlgoID will be NULL      
      cAlgoID = __ski_getCacheAlgoID(cNode, as2, algoID, create);
    }    
  }
  
  if (cAlgoID != NULL)
  {
    // Now where we have the entrance point, find the data
    if (cAlgoID->cacheData != NULL)
    {
      cData = cAlgoID->cacheData;
    }
    else
    {
      if (create)
      {
        cData = ___ski_createCacheData(asn, ski, algoID, NULL, false);
        cAlgoID->cacheData = cData;
        found = true;
      }
    }
    
    while (!found && (cData != NULL))
    {
      cmp = memcmp(ski, cData->ski, SKI_LENGTH);
      if (cmp < 0)
      {
        // We need to insert
        if (create)
        {
          cData = ___ski_createCacheData(asn, ski, algoID, NULL, false);
          if (prev != NULL)
          {
            cData->next = prev->next;
            prev->next  = cData;            
          }
          else
          {
            cData->next        = cAlgoID->cacheData;
            cAlgoID->cacheData = cData;
          }
          found = true;
        }
        else
        {
          cData = NULL;
        }
        continue;
      }
      if (cmp == 0)
      {
        found = true;
        continue;
      }
      prev  = cData;
      cData = cData->next;              
    }
  }

  if (!found)
  {
    cData = NULL;
  }
  
  return cData;
}

////////////////////////////////////////////////////////////////////////////////
// HEADER FILE FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

/**
 * Create and initialize as SKI cache.
 * 
 * The parameter specifies a callback function with the following functionality:
 * + Callback function to signal SKI changes. This function gets called by the
 * + cache handler for each SKI modification that might impact the update status.
 * + The receiver of this callback needs to determine if the update will be
 * + re-validated. (most likely yes for SKI_NEW and SKI_REMOVED, ADD and DEL
 * + should not affect the validation result (possible key roll over).
 * + 
 * + @param skiStatus one or more SKI's (keys) of the update changed.
 * + @param updateID The update that is related to the SKI
 * 
 * @param keyChange The callback for the key Change - See description above
 * 
 * @return Pointer to the SKI cache or NULL.
 */
SKI_CACHE* ski_createCache(void (*callback)(e_SKI_status, SRxUpdateID*))
{
  _SKI_CACHE* ski_cache = NULL;
  
  if ( callback != NULL)
  {
    ski_cache = malloc(sizeof(_SKI_CACHE));
    memset (ski_cache, sizeof(_SKI_CACHE), 0);
  }
  
  return (SKI_CACHE*)ski_cache;
}

/**
 * Frees all allocated resources.
 *
 * @param cache The SKI cache that needs to be removed.
 */
void ski_releaseCache(SKI_CACHE* cache)
{
  if (cache != NULL)
  {    
    _SKI_CACHE* _cache = (_SKI_CACHE*)cache;
    free (_cache);
  }
}



/**
 * Register the update with the ski cache. This method scans through the 
 * the BGPSEC secure path and extracts all SKI's and their associated algorithm
 * id and registers the SKI's in the SKI cache and assigns the update ID's to 
 * the SKI's. If this process notices that not one signature block can be 
 * validated due to missing keys, it will return SKIVAL_INVALID. If at least one
 * signature block had keys registered to all found SKI's the return value will
 * be SKIVAL_UNKNOWN. If the handed update is not a BGPSEC update, the return
 * value will be SKIVAL_ERROR.
 * the return value of SKIVAL_UNKNOWN does require a complete BGPSEC path 
 * validation to retrieve the correct BGPSEC path validation result.
 * 
 * @param cache The SKI cache.
 * @param updateID The ID of the BGPSec update
 * @param bgpsec The BGPsec_PATH attribute.
 * 
 * @return REGVAL_ERROR if not bgpsec update, REGVAL_INVALID if at least one key 
 * is missing in all signature blocks, REGVAL_UNKNOWN if all keys are available.
 */
e_Upd_RegRes ski_registerUpdate(SKI_CACHE* cache, SRxUpdateID* updateID, 
                                SCA_BGP_PathAttribute* bgpsec)
{
  #define _BGPSEC_MAX_SIG_BLOCKS 2

  _SKI_CACHE_DATA* cData = NULL;  

  SCA_BGPSEC_SecurePath*        securePath  = NULL;
  SCA_BGPSEC_SecurePathSegment* pathSegment = NULL;
  SCA_BGPSEC_SignatureBlock*    sigBlocks[_BGPSEC_MAX_SIG_BLOCKS] = {NULL, NULL};
  SCA_BGPSEC_SignatureSegment*  sigSement   = NULL;
 
  int numSegments  = 0;
  int numBlocks    = 0;
  u_int8_t* stream = (u_int8_t*)bgpsec;

  e_Upd_RegRes retVal = REGVAL_ERROR;
  
  if (bgpsec != NULL)
  {
    // Now figure out the type of path information  
    stream += sizeof(SCA_BGP_PathAttribute);
    // Contains the length of SecurePath and all Signature blocks.
    u_int16_t remainder = 0;  
    if ((bgpsec->flags & BGP_UPD_A_FLAGS_EXT_LENGTH) == 0)
    {
      remainder = *stream;
      remainder--;
      stream++;
    }
    else
    {
      // Extended message length (2 bytes)
      remainder = ntohs(*((u_int16_t*)stream));
      remainder -= 2;
      stream    += 2;
    }    
    if (remainder <= 0) { return retVal; }
    
    // Now stream is located at the Secure_Path element.
    securePath  = (SCA_BGPSEC_SecurePath*)stream;
    numSegments = ((ntohs(securePath->length)-2) / 6);
    // Now move stream to first secure path segment
    remainder  -= 2;
    if (remainder <= 0)
    { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
      return retVal; 
    }
    stream     += 2;
    pathSegment = (SCA_BGPSEC_SecurePathSegment*)stream;
    
    // Now move stream to signature block
    remainder  -= (numSegments * 6);
    // here < 0 because we might only have no signature block
    if (remainder < 0) 
    { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
      return retVal; 
    }
    if (remainder > 0)
    {
      stream += (numSegments * 6);
      sigBlocks[0] = (SCA_BGPSEC_SignatureBlock*)stream;
      numBlocks++;

      if (remainder > sigBlocks[0]->length)
      {
        numBlocks++;
        int length = ntohs(sigBlocks[0]->length);
        remainder  -= length;
        if (remainder < 0)
        { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
          return retVal; 
        }
        stream     += length;
        sigBlocks[1] = (SCA_BGPSEC_SignatureBlock*)stream;
        // Now move back to set the first signature segment pointer.
        stream     -= length;
      }
      // Now we MUST have a remainder of zero, otherwise the attribute is 
      // malformed.
    }
    if (remainder != 0) 
    { LOG(LEVEL_ERROR, "Malformed BGPsec update, UpdateID[0x%X]\n", updateID);
      return retVal; 
    }
    
    retVal = REGVAL_INVALID;
    
    SCA_BGPSEC_SignatureBlock* sigBlock = sigBlocks[0];
    int idx = 0;
    u_int32_t* asn_list = malloc(sizeof(u_int32_t) * numSegments);
    memset(asn_list, sizeof(u_int32_t) * numSegments, 0);
    
    for (idx = 0; idx < numSegments; idx ++)
    {
      asn_list[idx] = ntohl(pathSegment->asn);
      if (idx < numSegments)
      {
        // Jump to the next segment
        pathSegment++;
      }
    }
    
    // Do this for each signature block
    while (sigBlock != NULL)
    {
      int keyCount = 0;
      u_int8_t algoID = sigBlock->algoID;
      // Move the stream to the signature block
      stream = (u_int8_t*)sigBlock;
      // Move the stream to the next signature segment
      stream += sizeof(SCA_BGPSEC_SignatureBlock);
      for (idx = 0; idx < numSegments; idx ++)
      {
        // Set the signatue segment
        sigSement = (SCA_BGPSEC_SignatureSegment*)stream;
        cData = _getCacheData(cache, asn_list[idx], sigSement->ski, algoID, true);
        if (cData->counter > 0)
        {
          // Yes we have a key for that particular ASN/SKI/algo combo
          keyCount++;
        }
        // Now register the UpdateID with this cData
        __ski_addUpdateCacheUID(cData, updateID, _SKI_UPD_SHARED);
        
        // Now move to the next signature segment if available
        if (idx < numSegments)
        {
          // Jump to the next segment
          stream += sigSement->siglen;          
        }
      }

    }
    
    memset(asn_list, sizeof(u_int32_t) * numSegments, 0);
    free(asn_list);
    asn_list = NULL;
  }

  return retVal;
}

/**
 * Remove the update id from the SKI cache.
 * 
 * @param cache The SKI cache
 * @param updateID The update ID to be unregistered
 * @param bgpsec The BGPSEC path attribute.
 */
void ski_unregisterUpdate(SKI_CACHE* cache, SRxUpdateID* updateID,
                          SCA_BGPSEC_SecurePath* bgpsec)
{}

/**
 * Register the <SKI, algo-id> tuple in the SKI cache. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param asn The ASN the key is assigned to.
 * @param ski The 20 byte SKI of the key.
 * @param algoID The algorithm ID of the key.
 */
void ski_registerKey(SKI_CACHE* cache, u_int32_t asn, 
                     u_int8_t* ski, u_int8_t algoID)
{}

/** 
 * Remove the key counter from the <SKI, algo-id> tuple. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param asn The ASN the key is assigned to.
 * @param ski The 20 byte SKI of the key
 * @param algoID The algorithm ID of the key
 */
void ski_unregisterKey(SKI_CACHE* cache, u_int32_t asn, 
                       u_int8_t* ski, u_int8_t algoID)
{}

/**
 * Empty the SKI cache from un-used SKI numbers. This is a maintenance method
 * that can be computational extensive. It is not guaranteed that the cleanup
 * is done instantaneously.
 */
void ski_clean(SKI_CACHE* cache)
{}
