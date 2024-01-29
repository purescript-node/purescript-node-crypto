module Node.Crypto where

import Prelude

import Data.Either (Either(..))
import Data.Function.Uncurried (Fn2, mkFn2)
import Data.Maybe (Maybe(..))
import Data.Nullable (Nullable, toMaybe)
import Effect (Effect)
import Effect.Exception (Error)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, mkEffectFn2, runEffectFn1, runEffectFn2, runEffectFn3)
import Node.Buffer (Buffer)
import Node.Crypto.KeyObject (Asymmetric, KeyObject, Private, Public, Symmetric)

foreign import checkPrimeImpl :: forall a. EffectFn2 (Buffer) (Fn2 (Nullable Error) Boolean a) Unit

checkPrime :: forall a. Buffer -> (Either Error Boolean -> a) -> Effect Unit
checkPrime buffer cb =
  runEffectFn2 checkPrimeImpl buffer $ mkFn2 \err a -> cb case toMaybe err of
    Just err' -> Left err'
    Nothing -> Right a

foreign import checkPrimeOptsImpl :: forall a. EffectFn3 (Buffer) { checks :: Number } (Fn2 (Nullable Error) Boolean a) Unit

checkPrime' :: forall a. Buffer -> { checks :: Number } -> (Either Error Boolean -> a) -> Effect Unit
checkPrime' buffer checks cb =
  runEffectFn3 checkPrimeOptsImpl buffer checks $ mkFn2 \err a -> cb case toMaybe err of
    Just err' -> Left err'
    Nothing -> Right a

foreign import checkPrimeSyncImpl :: EffectFn1 (Buffer) Boolean

checkPrimeSync :: Buffer -> Effect Boolean
checkPrimeSync buffer =
  runEffectFn1 checkPrimeSyncImpl buffer

foreign import checkPrimeSyncOptsImpl :: EffectFn2 (Buffer) { checks :: Number } Boolean

checkPrimeSync' :: Buffer -> { checks :: Number } -> Effect Boolean
checkPrimeSync' buffer checks =
  runEffectFn2 checkPrimeSyncOptsImpl buffer checks

foreign import diffieHelmanImpl :: EffectFn1 ({ privateKey :: KeyObject (Asymmetric Private), publicKey :: KeyObject (Asymmetric Public)}) (Buffer)

-- | Computes the Diffie-Hellman secret based on a privateKey and a publicKey. 
-- | Both keys must have the same asymmetricKeyType, which must be one of 'dh' (for Diffie-Hellman), 
-- | 'ec' (for ECDH), 'x448', or 'x25519' (for ECDH-ES).
diffieHelman :: { privateKey :: KeyObject (Asymmetric Private), publicKey :: KeyObject (Asymmetric Public)} -> Effect Buffer
diffieHelman pair = runEffectFn1 diffieHelmanImpl pair

foreign import generateKeyHmacImpl :: forall a. EffectFn2 ({ length :: Number }) (EffectFn2 (Nullable Error) (KeyObject Symmetric) a) (Unit)

-- | Asynchronously generates a new random secret key of the given length. Length must be a multiple of 8 between `8 <= x <= 2^31-1`.
-- | If the value is not a multiple of 8, the generated key will be truncated to `Math.floor(length / 8)`.
-- |
-- | Note: The size of a generated HMAC key should not exceed the block size of the underlying hash function.
generateKeyHmac :: forall a. { length :: Number } -> (Either Error (KeyObject Symmetric) -> Effect a) -> Effect Unit
generateKeyHmac lengthNumber cb =
  runEffectFn2 generateKeyHmacImpl lengthNumber $ mkEffectFn2 \err a -> cb case toMaybe err of
    Just err' -> Left err'
    Nothing -> Right a

foreign import generateKeyAesImpl :: forall a. EffectFn2 ({ length :: Number }) (EffectFn2 (Nullable Error) (KeyObject Symmetric) a) (Unit)

-- | Asynchronously generates a new random secret key of the given length. Length must be `128`, `192`, or `256`.
generateKeyAes :: forall a. { length :: Number } -> (Either Error (KeyObject Symmetric) -> Effect a) -> Effect Unit
generateKeyAes lengthNumber cb =
  runEffectFn2 generateKeyAesImpl lengthNumber $ mkEffectFn2 \err a -> cb case toMaybe err of
    Just err' -> Left err'
    Nothing -> Right a
