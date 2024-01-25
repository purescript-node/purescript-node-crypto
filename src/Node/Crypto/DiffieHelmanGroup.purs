module Node.Crypto.DiffieHelmanGroupGroup 
  ( DiffieHelmanGroup
  , new
  , DHGroupName -- constructor intentionally not exported
  , modp14
  , modp15
  , modp16
  , modp17
  , modp18
  , computeSecret
  , generateKeys
  , getGenerator
  , getPrime
  , getPrivateKey
  , getPublicKey
  , verifyError
  , modp1
  , modp2
  , modp5
  ) where

import Prelude

import Data.Maybe (Maybe)
import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, runEffectFn1, runEffectFn2)
import Node.Buffer (Buffer)
import Node.Crypto.DiffieHelman (DiffieHelmanVerifyError)
import Node.Crypto.DiffieHelman as DH
import Unsafe.Coerce (unsafeCoerce)

-- | A `DiffieHellman` key exchange object whose
-- | keys cannot change after creation. Works
-- | the same as `DiffieHelman` but lacks the
-- | `setPublicKey` and `setPrivateKey` APIs.
foreign import data DiffieHelmanGroup :: Type

newtype DHGroupName = DHGroupName String

derive newtype instance Eq DHGroupName
derive newtype instance Show DHGroupName

-- | 2048 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 3
modp14 = DHGroupName "modp14" :: DHGroupName
-- | 3072 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 4
modp15 = DHGroupName "modp15" :: DHGroupName
-- | 4096 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 5
modp16 = DHGroupName "modp16" :: DHGroupName
-- | 6144 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 6
modp17 = DHGroupName "modp17" :: DHGroupName
-- | 8192 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 7
modp18 = DHGroupName "modp18" :: DHGroupName

-- | **Supported on Node but deprecated.** 768 bits, [RFC 2409](https://www.rfc-editor.org/rfc/rfc2409.txt) Section 6.1
modp1 = DHGroupName "modp1" :: DHGroupName
-- | **Supported on Node but deprecated.** (1024 bits, [RFC 2409](https://www.rfc-editor.org/rfc/rfc2409.txt) Section 6.2
modp2 = DHGroupName "modp2" :: DHGroupName
-- | **Supported on Node but deprecated.** 1536 bits, [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.txt) Section 2
modp5 = DHGroupName "modp5" :: DHGroupName

foreign import newImpl :: EffectFn1 (String) (DiffieHelmanGroup)

-- | Creates a `DiffieHellman` key exchange object using the supplied prime and a default generator value of `2`.
new :: DHGroupName -> Effect DiffieHelmanGroup
new (DHGroupName groupName) = runEffectFn1 newImpl groupName

foreign import computeSecretImpl :: EffectFn2 (DiffieHelmanGroup) (Buffer) (Buffer)

-- | Computes the shared secret using `otherPublicKey` as the other party's public key and returns the computed shared secret.
computeSecret :: Buffer -> DiffieHelmanGroup -> Effect Buffer
computeSecret otherPublicKey diffieHelman =
  runEffectFn2 computeSecretImpl diffieHelman otherPublicKey

foreign import generateKeysImpl :: EffectFn1 (DiffieHelmanGroup) (Buffer)

-- | Generates private and public Diffie-Hellman key values unless they have been generated or computed already, 
-- | and returns the public key. This public key should be transferred to the other party.
-- | 
-- | This function is a thin wrapper around [DH_generate_key()](https://www.openssl.org/docs/man3.0/man3/DH_generate_key.html). 
-- | In particular, once a private key has been generated or set, 
-- | calling this function only updates the public key but does not generate a new private key.
generateKeys :: DiffieHelmanGroup -> Effect Buffer
generateKeys diffieHelman = runEffectFn1 generateKeysImpl diffieHelman

foreign import getGeneratorImpl :: EffectFn1 (DiffieHelmanGroup) (Buffer)

-- | Returns the Diffie-Hellman generator
getGenerator :: DiffieHelmanGroup -> Effect Buffer
getGenerator diffieHelman = runEffectFn1 getGeneratorImpl diffieHelman

foreign import getPrimeImpl :: EffectFn1 (DiffieHelmanGroup) (Buffer)

-- | Returns the Diffie-Hellman prime
getPrime :: DiffieHelmanGroup -> Effect Buffer
getPrime diffieHelman = runEffectFn1 getPrimeImpl diffieHelman

foreign import getPrivateKeyImpl :: EffectFn1 (DiffieHelmanGroup) (Buffer)

-- | Returns the Diffie-Hellman private key
getPrivateKey :: DiffieHelmanGroup -> Effect Buffer
getPrivateKey diffieHelman = runEffectFn1 getPrivateKeyImpl diffieHelman

foreign import getPublicKeyImpl :: EffectFn1 (DiffieHelmanGroup) (Buffer)

-- | Returns the Diffie-Hellman public key
getPublicKey :: DiffieHelmanGroup -> Effect Buffer
getPublicKey diffieHelman = runEffectFn1 getPublicKeyImpl diffieHelman

-- | A bit field containing any warnings and/or errors resulting from a check performed during initialization of the DiffieHellman object.
verifyError :: DiffieHelmanGroup -> Maybe DiffieHelmanVerifyError
verifyError dh = DH.verifyError (unsafeCoerce dh)