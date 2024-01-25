module Node.Crypto.Hmac 
  ( Hmac
  , toDuplex
  , new
  , updateBuf
  , updateStr
  , digestBuf
  , digestStr
  ) where

import Prelude

import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, runEffectFn1, runEffectFn2, runEffectFn3)
import Node.Buffer (Buffer)
import Node.Encoding (Encoding, encodingToNode)
import Node.Stream (Duplex)
import Unsafe.Coerce (unsafeCoerce)

-- | The Hmac class is a utility for creating cryptographic HMAC digests. It can be used in one of two ways:
-- | - As a stream that is both readable and writable, where data is written to produce a computed HMAC digest on the readable side, or
-- | - Using the hmac.update() and hmac.digest() methods to produce the computed HMAC digest.
foreign import data Hmac :: Type

toDuplex :: Hmac -> Duplex
toDuplex = unsafeCoerce

foreign import newImpl :: EffectFn2 (String) (Buffer) (Hmac)

-- | Creates and returns an Hmac object that uses the given algorithm and key. 
-- | 
-- | The algorithm is dependent on the available algorithms supported by the version of 
-- | OpenSSL on the platform. Examples are 'sha256', 'sha512', etc. On recent releases of OpenSSL, 
-- | `openssl list -digest-algorithms` will display the available digest algorithms.
-- | 
-- | The key is the HMAC key used to generate the cryptographic HMAC hash. 
-- | If it was obtained from a cryptographically secure source of entropy, such as `crypto.randomBytes()` or `crypto.generateKey()`, 
-- | its length should not exceed the block size of algorithm (e.g., 512 bits for SHA-256).
new :: String -> Buffer -> Effect Hmac
new algorithm key =
  runEffectFn2 newImpl algorithm key

foreign import updateBufImpl :: EffectFn2 (Hmac) (Buffer) (Unit)

-- | Updates the `Hmac` content with the given data.
updateBuf :: Buffer -> Hmac -> Effect Unit
updateBuf buffer hmac =
  runEffectFn2 updateBufImpl hmac buffer

foreign import updateStrImpl :: EffectFn3 (Hmac) (String) (Encoding) (Unit)

-- | Updates the `Hmac` content with the given data.
updateStr :: String -> Encoding -> Hmac -> Effect Unit
updateStr string encoding hmac =
  runEffectFn3 updateStrImpl hmac string encoding

foreign import digestBufImpl :: EffectFn1 (Hmac) (Buffer)

-- | Calculates the `HMAC` digest of all of the data passed using `hmac.update()`.
-- | 
-- | The `Hmac` object can not be used again after `hmac.digest()` has been called. Multiple calls to `hmac.digest()` will result in an error being thrown.
digestBuf :: Hmac -> Effect Buffer
digestBuf hmac = runEffectFn1 digestBufImpl hmac

foreign import digestStrImpl :: EffectFn2 (Hmac) (String) (String)

-- | Calculates the `HMAC` digest of all of the data passed using `hmac.update()`.
-- | 
-- | The `Hmac` object can not be used again after `hmac.digest()` has been called. Multiple calls to `hmac.digest()` will result in an error being thrown.
digestStr :: Encoding -> Hmac -> Effect String
digestStr encoding hmac =
  runEffectFn2 digestStrImpl hmac (encodingToNode encoding)

