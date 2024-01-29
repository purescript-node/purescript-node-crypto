module Node.Crypto.KeyObject 
  ( KeyObjectType
  , Symmetric
  , Asymmetric
  , AsymmetricKeyType
  , Private
  , Public
  , KeyObject
  , KeyFormat
  , pem
  , der
  , jwk
  , DerKeyType
  , pkcs1
  , spki
  , newSecretKey
  , newPublicKeyBuf
  , newPublicKeyObj
  , NewPublicKeyOptions
  , newPrivateKeyBuf
  , newPrivateKeyObj
  , NewPrivateKeyOptions
  , assymetricKeyDetails
  , assymetricKeyType
  , symmetricKeySize
  , type'
  , keyType
  ) where

import Prelude

import Data.Function.Uncurried (Fn2, runFn2)
import Effect (Effect)
import Effect.Uncurried (EffectFn1, runEffectFn1)
import Foreign (Foreign)
import Node.Buffer (Buffer)
import Partial.Unsafe (unsafeCrashWith)
import Prim.Row as Row
import Unsafe.Coerce (unsafeCoerce)

data KeyObjectType

foreign import data Symmetric :: KeyObjectType
foreign import data Asymmetric :: AsymmetricKeyType -> KeyObjectType

data AsymmetricKeyType

foreign import data Private :: AsymmetricKeyType
foreign import data Public :: AsymmetricKeyType

-- | Node.js uses a `KeyObject` class to represent a symmetric or asymmetric key, and each kind of key exposes different functions. 
-- | 
-- | Most applications should consider using the new `KeyObject` API instead of passing keys as strings or Buffers 
-- | due to improved security features.
-- | 
-- | `KeyObject` instances can be passed to other threads via `postMessage()`. 
-- | The receiver obtains a cloned `KeyObject`, and the `KeyObject` does not need to be listed in the `transferList` argument.
foreign import data KeyObject :: KeyObjectType -> Type

instance Eq (KeyObject a) where
  eq a b = runFn2 eqKeyObjectImpl a b

foreign import eqKeyObjectImpl :: forall a. Fn2 (KeyObject a) (KeyObject a) Boolean

newtype KeyFormat = KeyFormat String

derive newtype instance Eq KeyFormat
derive newtype instance Ord KeyFormat
derive newtype instance Show KeyFormat

pem = KeyFormat "pem" :: KeyFormat
der = KeyFormat "der" :: KeyFormat
jwk = KeyFormat "jwk" :: KeyFormat

newtype DerKeyType = DerKeyType String

derive newtype instance Eq DerKeyType
derive newtype instance Ord DerKeyType
derive newtype instance Show DerKeyType

pkcs1 = DerKeyType "pkcs1" :: DerKeyType
spki = DerKeyType "spki" :: DerKeyType

foreign import newSecretKeyImpl :: EffectFn1 (Buffer) ((KeyObject Symmetric))

-- | Creates and returns a new key object containing a secret key for symmetric encryption or Hmac.
newSecretKey :: Buffer -> Effect (KeyObject Symmetric)
newSecretKey key = runEffectFn1 newSecretKeyImpl key

foreign import newPublicKeyBufImpl :: EffectFn1 (Buffer) (KeyObject (Asymmetric Public))

-- | Creates and returns a new key object containing a public key. Format is assumed to be 'pem';
newPublicKeyBuf :: Buffer -> Effect (KeyObject (Asymmetric Public))
newPublicKeyBuf buffer = runEffectFn1 newPublicKeyBufImpl buffer

foreign import newPublicKeyObjImpl :: forall r. EffectFn1 ({ | r }) ((KeyObject (Asymmetric Public)))

-- | Creates and returns a new key object containing a public key. 
newPublicKeyObj :: forall r trash. Row.Union r trash NewPublicKeyOptions => { | r } -> Effect (KeyObject (Asymmetric Public))
newPublicKeyObj r = runEffectFn1 newPublicKeyObjImpl r

type NewPublicKeyOptions =
  ( key :: Buffer
  , format :: KeyFormat
  , type :: DerKeyType
  )

foreign import newPrivateKeyBufImpl :: EffectFn1 (Buffer) ((KeyObject (Asymmetric Private)))

-- | Creates and returns a new key object containing a private key. Format is assumed to be 'pem';
newPrivateKeyBuf :: Buffer -> Effect (KeyObject (Asymmetric Private))
newPrivateKeyBuf buffer = runEffectFn1 newPrivateKeyBufImpl buffer

foreign import newPrivateKeyObjImpl :: forall r. EffectFn1 ({ | r }) ((KeyObject (Asymmetric Private)))

-- | Creates and returns a new key object containing a private key. 
-- | If the private key is encrypted, a passphrase must be specified. The length of the passphrase is limited to 1024 bytes.
newPrivateKeyObj :: forall r trash. Row.Union r trash NewPrivateKeyOptions => { | r } -> Effect (KeyObject (Asymmetric Private))
newPrivateKeyObj r = runEffectFn1 newPrivateKeyObjImpl r

type NewPrivateKeyOptions =
  ( key :: Buffer
  , format :: KeyFormat
  , type :: DerKeyType
  , passphrase :: Buffer
  )


-- | Returns an object whose fields depend on the algorithm of the `KeyObject`
-- | - `modulusLength`: `number` Key size in bits (RSA, DSA).
-- | - `publicExponent`: `bigint` Public exponent (RSA).
-- | - `hashAlgorithm`: `string` Name of the message digest (RSA-PSS).
-- | - `mgf1HashAlgorithm`: `string` Name of the message digest used by MGF1 (RSA-PSS).
-- | - `saltLength`: `number` Minimal salt length in bytes (RSA-PSS).
-- | - `divisorLength`: `number` Size of q in bits (DSA).
-- | - `namedCurve`: `string` Name of the curve (EC).
-- | 
-- | This property exists only on asymmetric keys. Depending on the type of the key, this object contains information about the key. None of the information obtained through this property can be used to uniquely identify a key or to compromise the security of the key.
-- | 
-- | For RSA-PSS keys, if the key material contains a RSASSA-PSS-params sequence, the hashAlgorithm, mgf1HashAlgorithm, and saltLength properties will be set.
-- | 
-- | Other key details might be exposed via this API using additional attributes.
foreign import assymetricKeyDetails :: forall x. KeyObject (Asymmetric x) -> Foreign

-- | For asymmetric keys, this property represents the type of the key. Supported key types are:
-- | - 'rsa' (OID 1.2.840.113549.1.1.1)
-- | - 'rsa-pss' (OID 1.2.840.113549.1.1.10)
-- | - 'dsa' (OID 1.2.840.10040.4.1)
-- | - 'ec' (OID 1.2.840.10045.2.1)
-- | - 'x25519' (OID 1.3.101.110)
-- | - 'x448' (OID 1.3.101.111)
-- | - 'ed25519' (OID 1.3.101.112)
-- | - 'ed448' (OID 1.3.101.113)
-- | - 'dh' (OID 1.2.840.113549.1.3.1)
-- | This property is undefined for unrecognized KeyObject types and symmetric keys.
foreign import assymetricKeyType :: forall x. KeyObject (Asymmetric x) -> String

-- | For secret keys, this property represents the size of the key in bytes. This property is undefined for asymmetric keys.
foreign import symmetricKeySize :: KeyObject Symmetric -> Number

foreign import typeImpl :: forall a. KeyObject a -> String

-- | Depending on the type of this KeyObject, this property is either 'secret' for secret (symmetric) keys, 
-- | 'public' for public (asymmetric) keys or 'private' for private (asymmetric) keys.
type' :: forall a. KeyObject a -> String
type' ko = typeImpl ko

-- | Eliminator for a KeyObject when one doesn't know what the `type` is.
keyType 
  :: forall x a
   . KeyObject x 
  -> (KeyObject Symmetric -> a)
  -> (KeyObject (Asymmetric Public) -> a)
  -> (KeyObject (Asymmetric Private) -> a)
  -> a
keyType ko onSym onPub onPriv = case type' ko of
  "secret" -> onSym $ (unsafeCoerce :: _ -> KeyObject Symmetric) ko
  "public" -> onPub $ (unsafeCoerce :: _ -> KeyObject (Asymmetric Public)) ko
  "private" -> onPriv $ (unsafeCoerce :: _ -> KeyObject (Asymmetric Private)) ko
  ty -> unsafeCrashWith $ "Impossible key type: " <> ty
