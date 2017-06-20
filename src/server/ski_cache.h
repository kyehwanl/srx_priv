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
 * 0.1.0.0  - 2017/06/19 - oborchert
 *            * modified function header for registering key ski's 
 *          - 2017/06/14 - oborchert
 *            * File created
 */
#ifndef SKI_CACHE_H
#define SKI_CACHE_H

#include <srx/srxcryptoapi.h>
#include "shared/srx_defs.h"

/** This enumeration is used to hint of a BGPSEC path validation is needed or 
 * not needed. If the registration determines that a validation will result in
 * invalid due to missing keys, the return valid is REGVAL_INVALID.*/
typedef enum {
  /** An ERROR during registration */
  REGVAL_ERROR,
  /** Due to missing keys a BGPSEC path validation will return INVALID*/
  REGVAL_INVALID,
  /** All keys are available, BGPSEC path validation can not be determined here.
   * A complete BGPsec path validation needs to be performed. */
  REGVAL_UNKNOWN,
} e_Upd_RegRes;

/** This enumeration allows to specify what kind of SKI change was performed. */
typedef enum {
  /** The SKI was newly added to the system */
  SKI_NEW,
  /** The SKI counter was increased. */
  SKI_ADD,
  /** The SKI counter was decreased but is above 0. */
  SKI_DEL,
  /** The SKI was removed (counter == 0) */
  SKI_REMOVED
} e_SKI_status;

/** The SKI_CACHE type */
typedef void SKI_CACHE;

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
 * @param callback The callback for the key Change - See description above
 * 
 * @return Pointer to the SKI cache or NULL.
 */
SKI_CACHE* createSKICache(void (*callback)(e_SKI_status, SRxUpdateID*));

/**
 * Frees all allocated resources.
 *
 * @param cache The SKI cache that needs to be removed.
 */
void releaseSKICache(SKI_CACHE* cache);

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
                               SCA_BGPSEC_SecurePath* bgpsec);

/**
 * Remove the update id from the SKI cache.
 * 
 * @param cache The SKI cache
 * @param updateID The update ID to be unregistered
 */
void unregisterUpdateSKI(SKI_CACHE* cache, SRxUpdateID* updateID);

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
                    u_int32_t asn);

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
                      u_int32_t asn);

/**
 * Empty the SKI cache from un-used SKI numbers. This is a maintenance method
 * that can be computational extensive. It is not guaranteed that the cleanup
 * is done instantaneously.
 */
void clean(SKI_CACHE* cache);
#endif /* SKI_CACHE_H */
