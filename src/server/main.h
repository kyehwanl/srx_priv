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
 * SRx Server - main header.
 *
 * In this version the SRX server only can connect to once RPKI VALIDATION CACHE
 * MULTI CACHE will be part of a later release.
 *
 * @version 0.5.0.0
 *
 *
 * Changelog:
 * -----------------------------------------------------------------------------
 * 0.5.0.0  - 2017/06/21 - borchert
 *            * Created to resolve compiler warnings
 */

#ifndef MAIN_H
#define MAIN_H

#include <srx/srxcryptoapi.h>

/**
 * Return the pointer to CAPI
 * 
 * @return the pointer to CAPI
 * 
 * @since 0.5.0.0
 */
SRxCryptoAPI* getSrxCAPI();


#endif /* MAIN_H */

