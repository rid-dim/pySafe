// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

#ifndef bindgen_safe_appobject_cacheh
#define bindgen_safe_appobject_cacheh


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// Object handle associated with objects. In normal C API one would expect rust
/// code to pass pointers to opaque object to C. C code would then need to pass
/// these pointers back each time they needed rust code to execute something on
/// those objects. However our code base deals with communication over Web
/// framework (like webservers for instance). Hence it is not possible to pass
/// pointers to remote apps interfacing with us. Pointers represent handle to
/// actual object.  Using similar concept, we instead pass `ObjectHandle` type
/// over Web interface and manage the objects ourselves. This leads to extra
/// type and memory safety and no chance of Undefined Behaviour.  Passing of
/// pointer handles to C is replaced by passing of `ObjectHandle` to remote apps
/// which they will use to do RPC's.
typedef uint64_t ObjectHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle CipherOptHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle EncryptPubKeyHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle EncryptSecKeyHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle MDataEntriesHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle MDataEntryActionsHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle MDataPermissionsHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle SelfEncryptorReaderHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle SelfEncryptorWriterHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle SignPubKeyHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle SignSecKeyHandle;

/// Disambiguating `ObjectHandle`
typedef ObjectHandle FileContextHandle;



#ifdef __cplusplus
}
#endif


#endif
