// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_corearraysh
#define bindgen_safe_corearraysh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Array containing public key bytes.
typedef uint8_t const* AsymPublicKey;

/// Array containing private key bytes.
typedef uint8_t const* AsymSecretKey;

/// Array containing nonce bytes.
typedef uint8_t const* AsymNonce;

/// Array containing private key bytes.
typedef uint8_t const* SymSecretKey;

/// Array containing nonce bytes.
typedef uint8_t const* SymNonce;

/// Array containing sign public key bytes.
typedef uint8_t const* SignPublicKey;

/// Array containing sign private key bytes.
typedef uint8_t const* SignSecretKey;

/// Array containing `XorName` bytes.
typedef uint8_t const* XorNameArray;



#ifdef __cplusplus
}
#endif


#endif
