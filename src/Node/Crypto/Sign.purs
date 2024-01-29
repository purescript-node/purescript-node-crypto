module Node.Crypto.Sign 
  ( Sign
  , new
  , updateBuf
  , updateStr
  , sign
  , SignOptions
  , signObj
  ) where

import Prelude

import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, runEffectFn1, runEffectFn2, runEffectFn3)
import Node.Buffer (Buffer)
import Node.Crypto.KeyObject (Asymmetric, KeyObject, NewPrivateKeyOptions, Private)
import Node.Crypto.RsaOptions (SaltLength, SignPadding)
import Node.Encoding (Encoding, encodingToNode)
import Prim.Row as Row

-- | The `Sign` class is a utility for generating signatures. It can be used in one of two ways:
-- | - As a writable stream, where data to be signed is written and the `sign.sign()` method is used to generate and return the signature, or
-- | - Using the `sign.update()` and `sign.sign()` methods to produce the signature.
-- | The `crypto.createSign()` method is used to create Sign instances. 
-- |
-- | Note: these PureScript bindings do not provide an option for the Writable stream options variant of `createSign`.
foreign import data Sign :: Type

foreign import newImpl :: EffectFn1 (String) (Sign)

-- | Creates and returns a `Sign` object that uses the given algorithm. 
-- | Use `crypto.getHashes()` to obtain the names of the available digest algorithms. 
-- | 
-- | In some cases, a `Sign` instance can be created using the name of a signature algorithm, 
-- | such as 'RSA-SHA256', instead of a digest algorithm. 
-- | This will use the corresponding digest algorithm. This does not work for all signature algorithms, 
-- | such as 'ecdsa-with-SHA256', so it is best to always use digest algorithm names.
new :: String -> Effect Sign
new algorithm = runEffectFn1 newImpl algorithm

foreign import updateBufImpl :: EffectFn2 (Sign) (Buffer) (Unit)

-- | Updates the Sign content with the given data
updateBuf :: Buffer -> Sign -> Effect Unit
updateBuf buffer signVal =
  runEffectFn2 updateBufImpl signVal buffer

foreign import updateStrImpl :: EffectFn3 (Sign) (String) (String) (Unit)

-- | Updates the Sign content with the given data
updateStr :: String -> Encoding -> Sign -> Effect Unit
updateStr dat enc signVal =
  runEffectFn3 updateStrImpl signVal dat (encodingToNode enc)

foreign import signKeyObjectImpl :: EffectFn2 (Sign) (KeyObject (Asymmetric Private)) (Buffer)

-- | Calculates the signature on all the data passed through using either `sign.update()` or `sign.write()`.
-- | 
-- | The `Sign` object can not be again used after `sign.sign()` method has been called. Multiple calls to `sign.sign()` will result in an error being thrown.
sign :: KeyObject (Asymmetric Private) -> Sign -> Effect Buffer
sign keyObject signVal =
  runEffectFn2 signKeyObjectImpl signVal keyObject

foreign import signObjImpl :: forall r. EffectFn2 (Sign) ({ | r }) (Buffer)

-- | Options for DSA and ECDSA:
-- | `dsaEncoding`: For DSA and ECDSA, this option specifies the format of the generated signature. It can be one of the following:
-- |   - 'der' (default): DER-encoded ASN.1 signature structure encoding (r, s).
-- |   - 'ieee-p1363': Signature format r || s as proposed in IEEE-P1363.
-- |
-- | Options for RSA:
-- | `padding`: `RSA_PKCS1_PSS_PADDING` will use `MGF1` with the same hash function used to sign the message 
-- |    as specified in section 3.1 of [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.txt), 
-- |    unless an MGF1 hash function has been specified as 
-- |    part of the key in compliance with section 3.3 of [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.txt).
-- | `saltLength`: Salt length for when padding is `RSA_PKCS1_PSS_PADDING`. 
-- |    The special value `crypto.constants.RSA_PSS_SALTLEN_DIGEST` sets the salt length to the digest size, 
-- |    `crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN` (default) sets it to the maximum permissible value.
type SignOptions =
  ( dsaEncoding :: String
  , padding :: SignPadding
  , saltLength :: SaltLength
  | NewPrivateKeyOptions
  )

signObj :: forall r trash. Row.Union r trash SignOptions => { | r } -> Sign -> Effect Buffer
signObj r signVal =
  runEffectFn2 signObjImpl signVal r
