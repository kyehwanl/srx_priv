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
#include "server/ski_cache.h"

/** The SKI center value. */
#define _SKI_CENTER_VAL 128

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
 * @version 0.1.0.0
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.1.0.0  - 2017/06/14 - oborchert
 *            * File created
 */
typedef struct _ski_node {
  /** The byte value of this particular node */
  u_int8_t   value;
  /** The level within the SKI 1..20 */
  u_int8_t   level;
  /** The parent node */
  struct _ski_node* parent;
  /** The node to the left */
  struct _ski_node* left;
  /** The node to the right */
  struct _ski_node* right;
  /** The child - its the SKI-LEAF of SKI_NODE if level < SKI_LENGTH */
  void*      child;
} _SKI_NODE;

typedef struct _ski_leaf {
  struct _ski_leaf* next;
  u_int32_t asn;
  u_int16_t counter;
} _SKI_LEAF;

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
  
  /** The SKI root node. It the element with the value 128 */
  _SKI_NODE* rootNode;  
  /** The number of SKI_NODES stored. */
  int nodes;
  /** The number of SKI_LEAVS stored. */
  int leavs;
} _SKI_CACHE;

/**
 * Return the last SKI Node that will contain the SKI LEAF. This function 
 * generates the SKI tree up to the last node.
 * 
 * @param cache The SKI cache
 * @param complete_ski The complete SKI number
 * @param pos the position in the SKI number
 * @param algoID The algorithmID
 * 
 * @return the SKI Node or null
 */
static _SKI_NODE* getSKI_NODE(_SKI_NODE* node, char* complete_ski, 
                                 u_int8_t pos, u_int8_t algoID)
{
  _SKI_NODE* retNode = node;
  
  if (node != NULL) 
  {
    if (pos < SKI_LENGTH)
    {    
      u_int8_t num = (u_int8_t)complete_ski[pos];
      // Now find the retNode that matches the num value
      while ((retNode != NULL) && (num < retNode->value))
      {
        retNode = retNode->left;
      }
      while ((retNode != NULL) && (num > retNode->value))
      {
        retNode = retNode->right;        
      }
      if (retNode != NULL)
      {
        if ((retNode->level+1) < SKI_LENGTH)
        {
          retNode = getSKI_NODE(retNode->child, complete_ski, pos++, algoID);
        }
      }
    }
  
    // Generate the tree down to the node
    if (retNode == NULL)
    {
      //node->child
    }
  }
  
  return retNode;
}

/**
 * Create an empty SKI node.
 * 
 * @param cache The cache this node is part of
 * @param parent The parent node or NULL if this is of level 1
 * 
 * @return the ski node.
 */
static _SKI_NODE* _createSKI_NODE(_SKI_CACHE* cache, void* parent)
{
  _SKI_NODE* node = malloc(sizeof(_SKI_NODE));
  _SKI_NODE* parentNode = (_SKI_NODE*)parent;
  memset (node, sizeof(_SKI_NODE), 0);
  node->level = (parentNode == NULL ? 0 : (parentNode->level + 1));
  node->value = _SKI_CENTER_VAL;  
  cache->nodes++;
}

/**
 * Create an empty SKI node.
 * 
 * @param level The level of the SKI node
 * 
 * @return the ski node.
 */
static _SKI_NODE* _freeSKI_NODE(_SKI_CACHE* cache, _SKI_NODE* node)
{  
  
  
  cache->nodes--;
}

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
SKI_CACHE* createSKICache(void (*callback)(e_SKI_status, SRxUpdateID*))
{
  _SKI_CACHE* ski_cache = NULL;
  
  if ( callback != NULL)
  {
    ski_cache = malloc(sizeof(_SKI_CACHE));
    memset (ski_cache, sizeof(_SKI_CACHE), 0);
    ski_cache->keyChange = callback;
    ski_cache->rootNode = _createSKI_NODE(ski_cache, NULL);
  }
  
  return (SKI_CACHE*)ski_cache;
}

/**
 * Frees all allocated resources.
 *
 * @param cache The SKI cache that needs to be removed.
 */
void releaseSKICache(SKI_CACHE* cache)
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
 * @param bgpsec The BGPSEC path attribute.
 * 
 * @return SKIVAL_ERROR if not bgpsec update, SKIVAL_INVALID if at least one key 
 * is missing in all signature blocks, SKIVAL_UNKNOWN if all keys are available.
 */
e_Upd_RegRes registerUpdateSKI(SKI_CACHE* cache, SRxUpdateID* updateID, 
                             SCA_BGPSEC_SecurePath* bgpsec)
{
  return (bgpsec == NULL) ? REGVAL_ERROR : REGVAL_UNKNOWN;
}

/**
 * Remove the update id from the SKI cache.
 * 
 * @param cache The SKI cache
 * @param updateID The update ID to be unregistered
 */
void unregisterUpdateSKI(SKI_CACHE* cache, SRxUpdateID* updateID)
{}

/**
 * Register the <SKI, algo-id> tuple in the SKI cache. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param ski The 20 byte SKI of the key.
 * @param algoID The algorithm ID of the key.
 * @param asn The ASN the key is assigned to.
 */
void registerKeySKI(SKI_CACHE* cache, u_int8_t* ski, u_int8_t algoID, 
                    u_int32_t asn)
{
  _SKI_CACHE* ski_cache;
  _SKI_LEAF*  ski_leave;
  
  
}

/** 
 * Remove the key counter from the <SKI, algo-id> tuple. This might trigger 
 * notifications for possible kick-starting of update validation.
 * 
 * @param cache The SKI cache.
 * @param ski The 20 byte SKI of the key
 * @param algoID The algorithm ID of the key
 * @param asn The ASN the key is assigned to.
 */
void unregisterKeySKI(SKI_CACHE* cache, u_int8_t* ski, u_int8_t algoID,
                      u_int32_t asn)
{}

/**
 * Empty the SKI cache from un-used SKI numbers. This is a maintenance method
 * that can be computational extensive. It is not guaranteed that the cleanup
 * is done instantaneously.
 */
void clean(SKI_CACHE* cache)
{}
