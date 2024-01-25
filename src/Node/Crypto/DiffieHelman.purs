module Node.Crypto.DiffieHelman 
  ( DiffieHelman
  , newFromPrime
  , newFromPrimeGeneratorBuf
  , newFromPrimeGeneratorNum
  , newFromPrimeLength
  , newFromPrimeLengthGenerator
  , computeSecret
  , generateKeys
  , getGenerator
  , getPrime
  , getPrivateKey
  , getPublicKey
  , setPrivateKey
  , setPublicKey
  , DiffieHelmanVerifyError(..)
  , verifyError
  ) where

import Prelude

import Data.Maybe (Maybe(..))
import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, runEffectFn1, runEffectFn2)
import Node.Buffer (Buffer)

-- | A `DiffieHellman` key exchange object that allows one
-- | to change the private/public keys after creation
-- | via `setPublicKey`/`setPrivateKey`. For an alternative
-- | that lacks these APIs, see `DiffieHelmanGroup`.
foreign import data DiffieHelman :: Type

foreign import newFromPrimeImpl :: EffectFn1 (Buffer) (DiffieHelman)

-- | Creates a `DiffieHellman` key exchange object using the supplied prime and a default generator value of `2`.
newFromPrime :: Buffer -> Effect DiffieHelman
newFromPrime prime = runEffectFn1 newFromPrimeImpl prime

foreign import newFromPrimeGeneratorBufImpl :: EffectFn2 (Buffer) (Buffer) (DiffieHelman)

-- | Creates a `DiffieHellman` key exchange object using the supplied prime and generator where the generator's type is `Buffer`.
newFromPrimeGeneratorBuf :: Buffer -> Buffer -> Effect DiffieHelman
newFromPrimeGeneratorBuf prime generator =
  runEffectFn2 newFromPrimeGeneratorBufImpl prime generator

foreign import newFromPrimeGeneratorNumImpl :: EffectFn2 (Buffer) (Number) (DiffieHelman)

-- | Creates a `DiffieHellman` key exchange object using the supplied prime and generator where the generator's type is `Number`.
newFromPrimeGeneratorNum :: Buffer -> Number -> Effect DiffieHelman
newFromPrimeGeneratorNum prime generator =
  runEffectFn2 newFromPrimeGeneratorNumImpl prime generator

foreign import newFromPrimeLengthImpl :: EffectFn1 (Number) (DiffieHelman)

newFromPrimeLength :: Number -> Effect DiffieHelman
newFromPrimeLength primeLength = runEffectFn1 newFromPrimeLengthImpl primeLength

foreign import newFromPrimeLengthGeneratorImpl :: EffectFn2 (Number) (Number) (DiffieHelman)

newFromPrimeLengthGenerator :: Number -> Number -> Effect DiffieHelman
newFromPrimeLengthGenerator primeLength generator =
  runEffectFn2 newFromPrimeLengthGeneratorImpl primeLength generator

foreign import computeSecretImpl :: EffectFn2 (DiffieHelman) (Buffer) (Buffer)

-- | Computes the shared secret using `otherPublicKey` as the other party's public key and returns the computed shared secret.
computeSecret :: Buffer -> DiffieHelman -> Effect Buffer
computeSecret otherPublicKey diffieHelman =
  runEffectFn2 computeSecretImpl diffieHelman otherPublicKey

foreign import generateKeysImpl :: EffectFn1 (DiffieHelman) (Buffer)

-- | Generates private and public Diffie-Hellman key values unless they have been generated or computed already, 
-- | and returns the public key. This public key should be transferred to the other party.
-- | 
-- | This function is a thin wrapper around [DH_generate_key()](https://www.openssl.org/docs/man3.0/man3/DH_generate_key.html). 
-- | In particular, once a private key has been generated or set, 
-- | calling this function only updates the public key but does not generate a new private key.
generateKeys :: DiffieHelman -> Effect Buffer
generateKeys diffieHelman = runEffectFn1 generateKeysImpl diffieHelman

foreign import getGeneratorImpl :: EffectFn1 (DiffieHelman) (Buffer)

-- | Returns the Diffie-Hellman generator
getGenerator :: DiffieHelman -> Effect Buffer
getGenerator diffieHelman = runEffectFn1 getGeneratorImpl diffieHelman

foreign import getPrimeImpl :: EffectFn1 (DiffieHelman) (Buffer)

-- | Returns the Diffie-Hellman prime
getPrime :: DiffieHelman -> Effect Buffer
getPrime diffieHelman = runEffectFn1 getPrimeImpl diffieHelman

foreign import getPrivateKeyImpl :: EffectFn1 (DiffieHelman) (Buffer)

-- | Returns the Diffie-Hellman private key
getPrivateKey :: DiffieHelman -> Effect Buffer
getPrivateKey diffieHelman = runEffectFn1 getPrivateKeyImpl diffieHelman

foreign import getPublicKeyImpl :: EffectFn1 (DiffieHelman) (Buffer)

-- | Returns the Diffie-Hellman public key
getPublicKey :: DiffieHelman -> Effect Buffer
getPublicKey diffieHelman = runEffectFn1 getPublicKeyImpl diffieHelman

foreign import setPrivateKeyImpl :: EffectFn2 (DiffieHelman) (Buffer) (Unit)

-- | Sets the Diffie-Hellman private key.
-- |
-- | This function does not automatically compute the associated public key. 
-- | Either use `diffieHellman.setPublicKey()` to manually provide the public key
-- | or use `diffieHellman.generateKeys()` to automatically derive it.
setPrivateKey :: Buffer -> DiffieHelman -> Effect Unit
setPrivateKey buffer diffieHelman =
  runEffectFn2 setPrivateKeyImpl diffieHelman buffer

foreign import setPublicKeyImpl :: EffectFn2 (DiffieHelman) (Buffer) (Unit)

-- | Sets the Diffie-Hellman public key. 
setPublicKey :: Buffer -> DiffieHelman -> Effect Unit
setPublicKey buffer diffieHelman =
  runEffectFn2 setPublicKeyImpl diffieHelman buffer

data DiffieHelmanVerifyError
  = DhCheckPNotSafePrime
  | DhCheckPNotPrime
  | DhUnableToCheckGenerator
  | DhNotSuitableGenerator

foreign import verifyErrorImpl :: DiffieHelman -> Int

-- | A bit field containing any warnings and/or errors resulting from a check performed during initialization of the DiffieHellman object.
verifyError :: DiffieHelman -> Maybe DiffieHelmanVerifyError
verifyError dh = do
  let result = verifyErrorImpl dh 
  if result == dh_check_p_not_safe_prime then Just DhCheckPNotSafePrime
  else if result == dh_check_p_not_prime then Just DhCheckPNotPrime
  else if result == dh_unable_to_check_generator then Just DhUnableToCheckGenerator
  else if result == dh_not_suitable_generator then Just DhNotSuitableGenerator
  else Nothing

foreign import dh_check_p_not_safe_prime :: Int
foreign import dh_check_p_not_prime :: Int
foreign import dh_unable_to_check_generator :: Int
foreign import dh_not_suitable_generator :: Int