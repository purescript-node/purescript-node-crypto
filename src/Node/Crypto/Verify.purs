module Node.Crypto.Verify 
  ( Verify
  , new
  , updateBuf
  , updateStr
  , verify
  , VerifyOptions
  , verifyObj
  ) where

import Prelude

import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, runEffectFn1, runEffectFn2, runEffectFn3)
import Node.Buffer (Buffer)
import Node.Crypto.KeyObject (Asymmetric, KeyObject, NewPublicKeyOptions, Public)
import Node.Crypto.RsaOptions (SaltLength, SignPadding)
import Node.Encoding (Encoding, encodingToNode)
import Prim.Row as Row

-- | The `Verify` class is a utility for verifying signatures. It can be used in one of two ways:
-- | - As a writable stream where written data is used to validate against the supplied signature, or
-- | - Using the `verify.update()` and `verify.verify()` methods to verify the signature.
foreign import data Verify :: Type

foreign import newImpl :: EffectFn1 (String) (Verify)

-- | Creates and returns a `Verify` object that uses the given algorithm. 
-- | Use `crypto.getHashes()` to obtain an array of names of the available signing algorithms. 
-- | 
-- | In some cases, a `Verify` instance can be created using the name of a signature algorithm, such as 'RSA-SHA256', 
-- | instead of a digest algorithm. This will use the corresponding digest algorithm. 
-- | This does not work for all signature algorithms, such as 'ecdsa-with-SHA256', 
-- | so it is best to always use digest algorithm names.
new :: String -> Effect Verify
new string = runEffectFn1 newImpl string

foreign import updateBufImpl :: EffectFn2 (Verify) (Buffer) (Unit)

-- | Updates the `Verify` content with the given data
-- | 
-- | This can be called many times with new data as it is streamed.
updateBuf :: Buffer -> Verify -> Effect Unit
updateBuf buffer verifyVal =
  runEffectFn2 updateBufImpl verifyVal buffer

foreign import updateStrImpl :: EffectFn3 (Verify) (String) (String) (Unit)

-- | Updates the `Verify` content with the given data
-- | 
-- | This can be called many times with new data as it is streamed.
updateStr :: String -> Encoding -> Verify -> Effect Unit
updateStr string encoding verifyVal =
  runEffectFn3 updateStrImpl verifyVal string (encodingToNode encoding)

foreign import verifyKeyObjectImpl :: EffectFn3 (Verify) (KeyObject (Asymmetric Public)) (Buffer) (Boolean)

-- | If object is not a KeyObject, this function behaves as if object had been passed to crypto.createPublicKey(). If it is an object, the following additional properties can be passed:
-- | 
-- |     dsaEncoding <string> For DSA and ECDSA, this option specifies the format of the signature. It can be one of the following:
-- |         'der' (default): DER-encoded ASN.1 signature structure encoding (r, s).
-- |         'ieee-p1363': Signature format r || s as proposed in IEEE-P1363.
-- | 
-- |     padding <integer> Optional padding value for RSA, one of the following:
-- |         crypto.constants.RSA_PKCS1_PADDING (default)
-- |         crypto.constants.RSA_PKCS1_PSS_PADDING
-- | 
-- |     RSA_PKCS1_PSS_PADDING will use MGF1 with the same hash function used to verify the message as specified in section 3.1 of RFC 4055, unless an MGF1 hash function has been specified as part of the key in compliance with section 3.3 of RFC 4055.
-- | 
-- |     saltLength <integer> Salt length for when padding is RSA_PKCS1_PSS_PADDING. The special value crypto.constants.RSA_PSS_SALTLEN_DIGEST sets the salt length to the digest size, crypto.constants.RSA_PSS_SALTLEN_AUTO (default) causes it to be determined automatically.
-- | 
-- | The signature argument is the previously calculated signature for the data, in the signatureEncoding. If a signatureEncoding is specified, the signature is expected to be a string; otherwise signature is expected to be a Buffer, TypedArray, or DataView.
-- | 
-- | The verify object can not be used again after verify.verify() has been called. Multiple calls to verify.verify() will result in an error being thrown.
verify :: KeyObject (Asymmetric Public) -> Buffer -> Verify -> Effect Boolean
verify keyObject signature verifyVal =
  runEffectFn3 verifyKeyObjectImpl verifyVal keyObject signature

foreign import verifyObjImpl :: forall r. EffectFn3 (Verify) { | r } (Buffer) (Boolean)


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
type VerifyOptions =
  ( dsaEncoding :: String
  , padding :: SignPadding
  , saltLength :: SaltLength
  | NewPublicKeyOptions
  )

-- | Verifies the provided data using the given object and signature.
-- | 
-- | The `signature` argument is the previously calculated `signature` for the data.
-- | 
-- | The `verify` object can NOT be used again after `verify.verify()` has been called. Multiple calls to `verify.verify()` will result in an error being thrown.
verifyObj :: forall r trash. Row.Union r trash VerifyOptions => { | r } -> Buffer -> Verify -> Effect Boolean
verifyObj obj signature verifyVal =
  runEffectFn3 verifyObjImpl verifyVal obj signature
