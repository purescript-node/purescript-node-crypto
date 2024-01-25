module Node.Crypto.ECDH 
  ( ECDH
  , getCurves
  , new
  , ECDHFormat(..)
  , toNodeEcdhFormat
  , convertKey
  , convertKey'
  , computeSecret
  , errorCodeIsInvalidPublicKey
  , generateKeys
  , generateKeys'
  , getPrivateKey
  , setPrivateKey
  , getPublicKey
  , getPublicKey'
  ) where


import Prelude

import Data.Either (Either(..))
import Effect (Effect)
import Effect.Exception (Error, throwException, try)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, runEffectFn1, runEffectFn2, runEffectFn3)
import Node.Buffer (Buffer)

-- | Elliptic Curve Diffie-Hellman (ECDH) key exchanges
foreign import data ECDH :: Type

foreign import newImpl :: EffectFn1 (String) (ECDH)

-- | Gets the array of supported elliptic curve names.
foreign import getCurves :: Effect (Array String)

new :: String -> Effect ECDH
new string = runEffectFn1 newImpl string

foreign import convertKeyImpl :: EffectFn2 (Buffer) (String) (Buffer)

-- | Converts the EC Diffie-Hellman public key specified by `key` and `curve` to the uncompressed format.
-- |
-- | Use `crypto.getCurves()` to obtain a list of available curve names. 
-- | On recent OpenSSL releases, `openssl ecparam -list_curves` will also
-- | display the name and description of each available elliptic curve.
convertKey :: Buffer -> String -> Effect Buffer
convertKey buffer string =
  runEffectFn2 convertKeyImpl buffer string

data ECDHFormat
  = Compressed
  | Uncompressed
  | Hybrid

instance Show ECDHFormat where
  show = case _ of
    Compressed -> "Compressed"
    Uncompressed -> "Uncompressed"
    Hybrid -> "Hybrid"

toNodeEcdhFormat :: ECDHFormat -> String
toNodeEcdhFormat = case _ of
  Compressed -> "compressed"
  Uncompressed -> "uncompressed"
  Hybrid -> "hybrid"

foreign import convertKeyFormatImpl :: EffectFn3 (Buffer) (String) (String) (Buffer)

-- | Converts the EC Diffie-Hellman public key specified by `key` and `curve` to the format specified by `format`. 
-- | The `format` argument specifies point encoding.
-- |
-- | Use `crypto.getCurves()` to obtain a list of available curve names. 
-- | On recent OpenSSL releases, `openssl ecparam -list_curves` will also
-- | display the name and description of each available elliptic curve.
-- |
-- | If format is not specified the point will be returned in 'uncompressed' format.
convertKey' :: Buffer -> String -> ECDHFormat -> Effect Buffer
convertKey' otherPublicKey string eCDHFormat =
  runEffectFn3 convertKeyFormatImpl otherPublicKey string (toNodeEcdhFormat eCDHFormat)

foreign import computeSecretImpl :: EffectFn2 (ECDH) (Buffer) (Buffer)

-- | Unsafe because the potential error with code `ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY` is not handled accordingly. Use `computeSecret` to do this automatically.
-- |
-- | Computes the shared secret using otherPublicKey as the other party's public key and returns the computed shared secret.
-- | 
-- | `ecdh.computeSecret` will throw an `ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY` error when `otherPublicKey` lies 
-- | outside of the elliptic curve. Since otherPublicKey is usually supplied from a remote user over an 
-- | insecure network, be sure to handle this exception accordingly.
unsafeComputeSecret :: Buffer -> ECDH -> Effect Buffer
unsafeComputeSecret otherPublicKey eCDH =
  runEffectFn2 computeSecretImpl eCDH otherPublicKey

-- | Computes the shared secret using `otherPublicKey` as the other party's public key.
-- | 
-- | Since `otherPublicKey` is usually supplied from a remote user over an insecure network, `otherPublicKey` may lie outside of the elliptic curve. 
-- |
-- | Returns `Left error` when `otherPublicKey` lies outside of the elliptic curve.
-- | Returns `Right buffer` otherwise where the buffer contains the computed shared secret.
computeSecret :: Buffer -> ECDH -> Effect (Either Error Buffer)
computeSecret otherPublicKey eCDH = do
  result <- try $ unsafeComputeSecret otherPublicKey eCDH
  case result of
    Right a -> pure $ Right a
    Left e 
      | errorCodeIsInvalidPublicKey e -> pure $ Left e
      | otherwise -> throwException e

-- | Safely checks whether `err.code === "ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY"`
foreign import errorCodeIsInvalidPublicKey :: Error -> Boolean

foreign import generateKeysImpl :: EffectFn1 (ECDH) (Buffer)

-- | Generates private and public EC Diffie-Hellman key values, and returns the public key in the 'uncompressed' format
generateKeys :: ECDH -> Effect Buffer
generateKeys ecdh = runEffectFn1 generateKeysImpl ecdh

foreign import generateKeysFormatImpl :: EffectFn2 (ECDH) (String) (Buffer)

-- | Generates private and public EC Diffie-Hellman key values, and returns the public key in the specified format
generateKeys' :: ECDHFormat -> ECDH -> Effect Buffer
generateKeys' ecdhFormat ecdh = runEffectFn2 generateKeysFormatImpl ecdh (toNodeEcdhFormat ecdhFormat) 

foreign import getPrivateKeyImpl :: EffectFn1 (ECDH) (Buffer)

-- | Returns the EC Diffie-Hellman private key
getPrivateKey :: ECDH -> Effect Buffer
getPrivateKey ecdh = runEffectFn1 getPrivateKeyImpl ecdh

foreign import getPublicKeyImpl :: EffectFn1 (ECDH) (Buffer)

-- | Returns the EC Diffie-Hellman public key in the 'uncompressed' format
getPublicKey :: ECDH -> Effect Buffer
getPublicKey ecdh = runEffectFn1 getPublicKeyImpl ecdh

foreign import getPublicKeyFormatImpl :: EffectFn2 (ECDH) (String) (Buffer)

-- | Returns the EC Diffie-Hellman public key in the specified format
getPublicKey' :: ECDHFormat -> ECDH -> Effect Buffer
getPublicKey' format ecdh = runEffectFn2 getPublicKeyFormatImpl ecdh (toNodeEcdhFormat format)

foreign import setPrivateKeyImpl :: EffectFn2 (ECDH) (Buffer) (Unit)

-- | Sets the EC Diffie-Hellman private key. 
-- | 
-- | If privateKey is not valid for the curve specified when the ECDH object was created, an error is thrown. 
-- | Upon setting the private key, the associated public point (key) is also generated and set in the ECDH object.
setPrivateKey :: Buffer -> ECDH -> Effect Unit
setPrivateKey buffer eCDH =
  runEffectFn2 setPrivateKeyImpl eCDH buffer
