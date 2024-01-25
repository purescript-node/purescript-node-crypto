module Node.Crypto.Cipher 
  ( Cipher
  , new
  , NewOptions
  , new'
  , toDuplex
  , finalBuf
  , finalStr
  , getAuthTag
  , setAAD
  , SetAADOptions
  , setAAD'
  , setAutoPadding
  , setAutoPadding'
  , updateBufBuf
  , updateBufStr
  , updateStrBuf
  , updateStrStr
  ) where


import Data.Nullable (Nullable)
import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, EffectFn3, EffectFn4, runEffectFn1, runEffectFn2, runEffectFn3, runEffectFn4)
import Node.Buffer (Buffer)
import Node.Encoding (Encoding, encodingToNode)
import Node.Stream (Duplex)
import Prim.Row as Row
import Unsafe.Coerce (unsafeCoerce)

-- | Instances of the `Cipher` class are used to encrypt data. The class can be used in one of two ways:
-- | - As a stream that is both readable and writable, where plain unencrypted data is written to produce encrypted data on the readable side, or
-- | - Using the `cipher.update()` and `cipher.final()` methods to produce the encrypted data.
foreign import data Cipher :: Type

foreign import newImpl :: EffectFn3 (String) (Buffer) (Nullable Buffer) (Cipher)

-- | Creates and returns a Cipher object, with the given `algorithm`, `key`, and `initialization vector` (IV).
-- | 
-- | Use `new'` instead of this function when using
-- | - A cipher in CCM or OCB mode as the `authTagLength` options is required and specifies the length of the authentication tag in bytes
-- | - A cipher in GCM mode and you want to use the `authTagLength` option to set the length of the authentication tag that is returned by `getAuthTag` (defaults to 16 bytes).
-- |
-- | For `chacha20-poly1305`, the `authTagLength` option defaults to 16 bytes.
-- | 
-- | The `algorithm` is dependent on OpenSSL, examples are 'aes192', etc. On recent OpenSSL releases,
-- | `openssl list -cipher-algorithms` will display the available cipher algorithms.
-- | 
-- | If the cipher does not need an IV, it may be null.
-- | 
-- | Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random. 
-- | They do not have to be secret: IVs are typically just added to ciphertext messages unencrypted. 
-- | It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret; 
-- | remember that an attacker must not be able to predict ahead of time what a given IV will be.
new :: String -> Buffer -> Nullable Buffer -> Effect Cipher
new algorithm key initializationBuffer =
  runEffectFn3 newImpl algorithm key initializationBuffer

foreign import newOptsImpl :: forall r. EffectFn4 (String) (Buffer) (Nullable Buffer) ({ | r }) (Cipher)

type NewOptions =
  ( authTagLength :: Number
  )

-- | Creates and returns a Cipher object, with the given `algorithm`, `key`, `initialization vector` (IV), and `options`.
-- | 
-- | The `options` argument controls stream behavior and is optional except when a cipher in CCM or OCB mode (e.g. 'aes-128-ccm') is used. 
-- | In that case, the `authTagLength` option is required and specifies the length of the authentication tag in bytes, see CCM mode. 
-- | In GCM mode, the `authTagLength` option is not required but can be used to set the length of the authentication tag that 
-- | will be returned by `getAuthTag()` and defaults to 16 bytes. 
-- | For `chacha20-poly1305`, the `authTagLength` option defaults to 16 bytes.
-- | 
-- | The `algorithm` is dependent on OpenSSL, examples are 'aes192', etc. On recent OpenSSL releases,
-- | `openssl list -cipher-algorithms` will display the available cipher algorithms.
-- | 
-- | If the cipher does not need an initialization vector, it may be null.
-- | 
-- | Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random. 
-- | They do not have to be secret: IVs are typically just added to ciphertext messages unencrypted. 
-- | It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret; 
-- | remember that an attacker must not be able to predict ahead of time what a given IV will be.
new' :: forall r trash. Row.Union r trash NewOptions => String -> Buffer -> Nullable Buffer -> { | r } -> Effect Cipher
new' algorithm key initializationBuffer options =
  runEffectFn4 newOptsImpl algorithm key initializationBuffer options

toDuplex :: Cipher -> Duplex
toDuplex = unsafeCoerce

foreign import finalBufImpl :: EffectFn1 (Cipher) (Buffer)

-- | Once the `cipher.final()` method has been called, 
-- | the `Cipher` object can no longer be used to encrypt data. 
-- | Attempts to call `cipher.final()` more than once will result in an error being thrown.
finalBuf :: Cipher -> Effect Buffer
finalBuf cipher = runEffectFn1 finalBufImpl cipher

foreign import finalStrImpl :: EffectFn2 (Cipher) (String) (Buffer)

-- | Once the `cipher.final()` method has been called, 
-- | the `Cipher` object can no longer be used to encrypt data. 
-- | Attempts to call `cipher.final()` more than once will result in an error being thrown.
-- |
-- | `cipher # finalStr UTF8`
finalStr :: Encoding -> Cipher -> Effect Buffer
finalStr encoding cipher = runEffectFn2 finalStrImpl cipher (encodingToNode encoding)

foreign import getAuthTagImpl :: EffectFn1 (Cipher) (Buffer)


-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `cipher.getAuthTag()` method returns a `Buffer` containing the authentication tag that has been computed from the given data.
-- | 
-- | The `cipher.getAuthTag()` method should only be called after encryption has been completed using the `cipher.final()` method.
-- | 
-- | If the `authTagLength` option was set during the `cipher` instance's creation, this function will return exactly `authTagLength` bytes.
getAuthTag :: Cipher -> Effect Buffer
getAuthTag cipher = runEffectFn1 getAuthTagImpl cipher

foreign import setAADImpl :: EffectFn2 (Cipher) (Buffer) (Cipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `cipher.setAAD()` method sets the value used for the _additional authenticated data_ (AAD) input parameter.
-- | 
-- | The `cipher.setAAD()` method must be called before `cipher.update()`.
setAAD :: Buffer -> Cipher -> Effect Cipher
setAAD buffer cipher =
  runEffectFn2 setAADImpl cipher buffer

type SetAADOptions =
  ( plainTextLength :: Number
  , encoding :: String
  )

foreign import setAADOptsImpl :: forall r. EffectFn3 (Cipher) (Buffer) ({ | r }) (Cipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `cipher.setAAD()` method sets the value used for the additional authenticated data (AAD) input parameter.
-- | 
-- | The `plaintextLength` option is optional for GCM and OCB. When using CCM, the `plaintextLength` option must 
-- | be specified and its value must match the length of the plaintext in bytes. See CCM mode.
-- | 
-- | The `cipher.setAAD()` method must be called before `cipher.update()`.
setAAD' 
  :: forall r trash
   . Row.Union r trash SetAADOptions
  => Buffer
  -> { | r }
  -> Cipher
  -> Effect Cipher
setAAD' buffer r cipher =
  runEffectFn3 setAADOptsImpl cipher buffer r

foreign import setAutoPaddingImpl :: EffectFn1 (Cipher) (Cipher)

-- | Sets the `cipher`'s `autoPadding` to `true`.
-- |
-- | When using block encryption algorithms, the `Cipher` class will automatically 
-- | add padding to the input data to the appropriate block size. To disable the default padding call `cipher.setAutoPadding(false)`.
-- |
-- | When `autoPadding` is `false`, the length of the entire input data must be a 
-- | multiple of the cipher's block size or `cipher.final()` will throw an error. 
-- | Disabling automatic padding is useful for non-standard padding, for instance using `0x0` instead of PKCS padding.
-- |
-- | The `cipher.setAutoPadding()` method must be called before `cipher.final()`.
setAutoPadding :: Cipher -> Effect Cipher
setAutoPadding cipher = runEffectFn1 setAutoPaddingImpl cipher

foreign import setAutoPaddingBoolImpl :: EffectFn2 (Cipher) (Boolean) (Cipher)

-- | When using block encryption algorithms, the `Cipher` class will automatically 
-- | add padding to the input data to the appropriate block size. To disable the default padding call `cipher.setAutoPadding(false)`.
-- |
-- | When `autoPadding` is `false`, the length of the entire input data must be a 
-- | multiple of the cipher's block size or `cipher.final()` will throw an error. 
-- | Disabling automatic padding is useful for non-standard padding, for instance using `0x0` instead of PKCS padding.
-- |
-- | The `cipher.setAutoPadding()` method must be called before `cipher.final()`.
setAutoPadding' :: Boolean -> Cipher -> Effect Cipher
setAutoPadding' boolean cipher =
  runEffectFn2 setAutoPaddingBoolImpl cipher boolean

foreign import updateBufBufImpl :: EffectFn2 (Cipher) (Buffer) (Buffer)

-- | Updates the `cipher`. This variant's input is `Buffer` and output is `Buffer`.
-- | 
-- | The `cipher.update()` method can be called multiple times with new data until `cipher.final()` is called. Calling `cipher.update()` after `cipher.final()` will result in an error being thrown.
updateBufBuf :: Buffer -> Cipher -> Effect Buffer
updateBufBuf buffer cipher =
  runEffectFn2 updateBufBufImpl cipher buffer

foreign import updateBufStrImpl :: EffectFn3 (Cipher) (Buffer) (String) (String)

-- | Updates the `cipher`. This variant's input is `Buffer` and output is `String` using the speified encoding.
-- | 
-- | The `cipher.update()` method can be called multiple times with new data until `cipher.final()` is called. Calling `cipher.update()` after `cipher.final()` will result in an error being thrown.
updateBufStr :: Buffer -> Encoding -> Cipher -> Effect String
updateBufStr buffer outputEncoding cipher =
  runEffectFn3 updateBufStrImpl cipher buffer (encodingToNode outputEncoding)

foreign import updateStrBufImpl :: EffectFn3 (Cipher) (String) (String) (Buffer)

-- | Updates the `cipher`. This variant's input is `String` using the specified encoding and output is `Buffer`.
-- | 
-- | The `cipher.update()` method can be called multiple times with new data until `cipher.final()` is called. Calling `cipher.update()` after `cipher.final()` will result in an error being thrown.
updateStrBuf :: String -> Encoding -> Cipher -> Effect Buffer
updateStrBuf string inputEncoding cipher =
  runEffectFn3 updateStrBufImpl cipher string (encodingToNode inputEncoding)

foreign import updateStrStrImpl :: EffectFn4 (Cipher) (String) (String) (String) (String)

-- | Updates the `cipher`. This variant's input is `String` using the first specified encoding and output is `String` using the second specified encoding.
-- | 
-- | The `cipher.update()` method can be called multiple times with new data until `cipher.final()` is called. Calling `cipher.update()` after `cipher.final()` will result in an error being thrown.
-- | ```
-- | updateStr cipher input inputEncoding outputEncoding
-- | ```
updateStrStr :: String -> Encoding -> Encoding -> Cipher -> Effect String
updateStrStr string inputEncoding outputEncoding cipher =
  runEffectFn4 updateStrStrImpl cipher string (encodingToNode inputEncoding) (encodingToNode outputEncoding)

