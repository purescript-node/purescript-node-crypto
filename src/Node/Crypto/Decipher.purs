module Node.Crypto.Decipher 
  ( Decipher
  , new
  , NewOptions
  , new'
  , toDuplex
  , finalBuf
  , finalStr
  , setAAD
  , SetAADOptions
  , setAAD'
  , setAuthTagBuf
  , setAuthTagStr
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

-- | Instances of the `Decipher` class are used to decrypt data. The class can be used in one of two ways:
-- | - As a stream that is both readable and writable, where plain encrypted data is written to produce unencrypted data on the readable side, or
-- | - Using the `dededecipher.update()` and `dededecipher.final()` methods to produce the unencrypted data.
foreign import data Decipher :: Type

foreign import newImpl :: EffectFn3 (String) (Buffer) (Nullable Buffer) (Decipher)

-- | Creates and returns a Decipher object, with the given `algorithm`, `key`, and `initialization vector` (IV).
-- | 
-- | Use `new'` instead of this function when using
-- | - A dedecipher in CCM or OCB mode as the `authTagLength` options is required and specifies the length of the authentication tag in bytes
-- | - A dedecipher in GCM mode and you want to use the `authTagLength` option to set the length of the authentication tag that is returned by `getAuthTag` (defaults to 16 bytes).
-- |
-- | For `chacha20-poly1305`, the `authTagLength` option defaults to 16 bytes.
-- | 
-- | The `algorithm` is dependent on OpenSSL, examples are 'aes192', etc. On recent OpenSSL releases,
-- | `openssl list -decipher-algorithms` will display the available dedecipher algorithms.
-- | 
-- | If the dedecipher does not need an IV, it may be null.
-- | 
-- | Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random. 
-- | They do not have to be secret: IVs are typically just added to dedeciphertext messages unencrypted. 
-- | It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret; 
-- | remember that an attacker must not be able to predict ahead of time what a given IV will be.
new :: String -> Buffer -> Nullable Buffer -> Effect Decipher
new algorithm key initializationBuffer =
  runEffectFn3 newImpl algorithm key initializationBuffer

foreign import newOptsImpl :: forall r. EffectFn4 (String) (Buffer) (Nullable Buffer) ({ | r }) (Decipher)

type NewOptions =
  ( authTagLength :: Number
  )

-- | Creates and returns a Decipher object, with the given `algorithm`, `key`, `initialization vector` (IV), and `options`.
-- | 
-- | The `options` argument controls stream behavior and is optional except when a decipher in CCM or OCB mode (e.g. 'aes-128-ccm') is used. 
-- | In that case, the `authTagLength` option is required and specifies the length of the authentication tag in bytes, see CCM mode. 
-- | In GCM mode, the `authTagLength` option is not required but can be used to set the length of the authentication tag that 
-- | will be returned by `getAuthTag()` and defaults to 16 bytes. 
-- | For `chacha20-poly1305`, the `authTagLength` option defaults to 16 bytes.
-- | 
-- | The `algorithm` is dependent on OpenSSL, examples are 'aes192', etc. On recent OpenSSL releases,
-- | `openssl list -cipher-algorithms` will display the available decipher algorithms.
-- | 
-- | If the decipher does not need an initialization vector, it may be null.
-- | 
-- | Initialization vectors should be unpredictable and unique; ideally, they will be cryptographically random. 
-- | They do not have to be secret: IVs are typically just added to deciphertext messages unencrypted. 
-- | It may sound contradictory that something has to be unpredictable and unique, but does not have to be secret; 
-- | remember that an attacker must not be able to predict ahead of time what a given IV will be.
new' :: forall r trash. Row.Union r trash NewOptions => String -> Buffer -> Nullable Buffer -> { | r } -> Effect Decipher
new' algorithm key initializationBuffer options =
  runEffectFn4 newOptsImpl algorithm key initializationBuffer options

toDuplex :: Decipher -> Duplex
toDuplex = unsafeCoerce

foreign import finalBufImpl :: EffectFn1 (Decipher) (Buffer)

-- | Returns any remaining dedeciphered contents.
-- |
-- | Once the `dedecipher.final()` method has been called, 
-- | the `Decipher` object can no longer be used to encrypt data. 
-- | Attempts to call `dedecipher.final()` more than once will result in an error being thrown.
finalBuf :: Decipher -> Effect Buffer
finalBuf dedecipher = runEffectFn1 finalBufImpl dedecipher

foreign import finalStrImpl :: EffectFn2 (Decipher) (String) (Buffer)

-- | Returns any remaining dedeciphered contents.
-- |
-- | Once the `dedecipher.final()` method has been called, 
-- | the `Decipher` object can no longer be used to encrypt data. 
-- | Attempts to call `dedecipher.final()` more than once will result in an error being thrown.
-- |
-- | `dedecipher # finalStr UTF8`
finalStr :: Encoding -> Decipher -> Effect Buffer
finalStr encoding dedecipher = runEffectFn2 finalStrImpl dedecipher (encodingToNode encoding)

foreign import setAADImpl :: EffectFn2 (Decipher) (Buffer) (Decipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `dedecipher.setAAD()` method sets the value used for the _additional authenticated data_ (AAD) input parameter.
-- | 
-- | The `dedecipher.setAAD()` method must be called before `dedecipher.update()`.
-- |
-- | When passing a string as the buffer, please consider 
-- | [caveats when using strings as inputs to cryptographic APIs](https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis).
setAAD :: Buffer -> Decipher -> Effect Decipher
setAAD buffer dedecipher =
  runEffectFn2 setAADImpl dedecipher buffer

type SetAADOptions =
  ( plainTextLength :: Number
  , encoding :: String
  )

foreign import setAADOptsImpl :: forall r. EffectFn3 (Decipher) (Buffer) ({ | r }) (Decipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `dedecipher.setAAD()` method sets the value used for the _additional authenticated data_ (AAD) input parameter.
-- | 
-- | The `options` argument is optional for GCM. The `plaintextLength` option is optional for GCM and OCB. When using CCM, the `plaintextLength` option must 
-- | be specified and its value must match the length of the plaintext in bytes. See CCM mode.
-- | 
-- | The `dedecipher.setAAD()` method must be called before `dedecipher.update()`.
-- |
-- | When passing a string as the buffer, please consider 
-- | [caveats when using strings as inputs to cryptographic APIs](https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis).
setAAD' 
  :: forall r trash
   . Row.Union r trash SetAADOptions
  => Buffer
  -> { | r }
  -> Decipher
  -> Effect Decipher
setAAD' buffer r dedecipher =
  runEffectFn3 setAADOptsImpl dedecipher buffer r

foreign import setAuthTagBufImpl :: EffectFn2 (Decipher) (Buffer) (Decipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `dedecipher.setAuthTag()` method is used to pass in the received authentication tag. 
-- | If no tag is provided, or if the decipher text has been tampered with, `dedecipher.final()` will throw, 
-- | indicating that the decipher text should be discarded due to failed authentication. 
-- | If the tag length is invalid according to [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) 
-- | or does not match the value of the `authTagLength` option, 
-- | `dedecipher.setAuthTag()` will throw an error.
-- | 
-- | The `dedecipher.setAuthTag()` method must be called before `dedecipher.update()` for CCM mode or before `dedecipher.final()` for GCM and OCB modes and chacha20-poly1305. 
-- |
-- | `dedecipher.setAuthTag()` can only be called once.
setAuthTagBuf :: Buffer -> Decipher -> Effect Decipher
setAuthTagBuf buf dedecipher = runEffectFn2 setAuthTagBufImpl dedecipher buf

foreign import setAuthTagStrImpl :: EffectFn3 (Decipher) (String) (String) (Decipher)

-- | When using an authenticated encryption mode (GCM, CCM, OCB, and chacha20-poly1305 are currently supported), 
-- | the `dedecipher.setAuthTag()` method is used to pass in the received authentication tag. 
-- | If no tag is provided, or if the decipher text has been tampered with, `dedecipher.final()` will throw, 
-- | indicating that the decipher text should be discarded due to failed authentication. 
-- | If the tag length is invalid according to [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) 
-- | or does not match the value of the `authTagLength` option, 
-- | `dedecipher.setAuthTag()` will throw an error.
-- | 
-- | The `dedecipher.setAuthTag()` method must be called before `dedecipher.update()` for CCM mode or before `dedecipher.final()` for GCM and OCB modes and chacha20-poly1305. 
-- |
-- | `dedecipher.setAuthTag()` can only be called once.
setAuthTagStr :: String -> Encoding -> Decipher -> Effect Decipher
setAuthTagStr str encoding dedecipher = runEffectFn3 setAuthTagStrImpl dedecipher str (encodingToNode encoding)

foreign import setAutoPaddingImpl :: EffectFn1 (Decipher) (Decipher)

-- | Sets the `dedecipher`'s `autoPadding` to `true`.
-- |
-- | When using block encryption algorithms, the `Decipher` class will automatically 
-- | add padding to the input data to the appropriate block size. To disable the default padding call `dedecipher.setAutoPadding(false)`.
-- |
-- | When `autoPadding` is `false`, the length of the entire input data must be a 
-- | multiple of the dedecipher's block size or `dedecipher.final()` will throw an error. 
-- | Disabling automatic padding is useful for non-standard padding, for instance using `0x0` instead of PKCS padding.
-- |
-- | The `dedecipher.setAutoPadding()` method must be called before `dedecipher.final()`.
setAutoPadding :: Decipher -> Effect Decipher
setAutoPadding dedecipher = runEffectFn1 setAutoPaddingImpl dedecipher

foreign import setAutoPaddingBoolImpl :: EffectFn2 (Decipher) (Boolean) (Decipher)

-- | When using block encryption algorithms, the `Decipher` class will automatically 
-- | add padding to the input data to the appropriate block size. To disable the default padding call `dedecipher.setAutoPadding(false)`.
-- |
-- | When `autoPadding` is `false`, the length of the entire input data must be a 
-- | multiple of the dedecipher's block size or `dedecipher.final()` will throw an error. 
-- | Disabling automatic padding is useful for non-standard padding, for instance using `0x0` instead of PKCS padding.
-- |
-- | The `dedecipher.setAutoPadding()` method must be called before `dedecipher.final()`.
setAutoPadding' :: Boolean -> Decipher -> Effect Decipher
setAutoPadding' boolean dedecipher =
  runEffectFn2 setAutoPaddingBoolImpl dedecipher boolean

foreign import updateBufBufImpl :: EffectFn2 (Decipher) (Buffer) (Buffer)

-- | Updates the `dedecipher`. This variant's input is `Buffer` and output is `Buffer`.
-- | 
-- | The `dedecipher.update()` method can be called multiple times with new data until `dedecipher.final()` is called. Calling `dedecipher.update()` after `dedecipher.final()` will result in an error being thrown.
updateBufBuf :: Buffer -> Decipher -> Effect Buffer
updateBufBuf buffer dedecipher =
  runEffectFn2 updateBufBufImpl dedecipher buffer

foreign import updateBufStrImpl :: EffectFn3 (Decipher) (Buffer) (String) (String)

-- | Updates the `dedecipher`. This variant's input is `Buffer` and output is `String` using the speified encoding.
-- | 
-- | The `dedecipher.update()` method can be called multiple times with new data until `dedecipher.final()` is called. Calling `dedecipher.update()` after `dedecipher.final()` will result in an error being thrown.
updateBufStr :: Buffer -> Encoding -> Decipher -> Effect String
updateBufStr buffer outputEncoding dedecipher =
  runEffectFn3 updateBufStrImpl dedecipher buffer (encodingToNode outputEncoding)

foreign import updateStrBufImpl :: EffectFn3 (Decipher) (String) (String) (Buffer)

-- | Updates the `dedecipher`. This variant's input is `String` using the specified encoding and output is `Buffer`.
-- | 
-- | The `dedecipher.update()` method can be called multiple times with new data until `dedecipher.final()` is called. Calling `dedecipher.update()` after `dedecipher.final()` will result in an error being thrown.
updateStrBuf :: String -> Encoding -> Decipher -> Effect Buffer
updateStrBuf string inputEncoding dedecipher =
  runEffectFn3 updateStrBufImpl dedecipher string (encodingToNode inputEncoding)

foreign import updateStrStrImpl :: EffectFn4 (Decipher) (String) (String) (String) (String)

-- | Updates the `dedecipher`. This variant's input is `String` using the first specified encoding and output is `String` using the second specified encoding.
-- | 
-- | The `dedecipher.update()` method can be called multiple times with new data until `dedecipher.final()` is called. Calling `dedecipher.update()` after `dedecipher.final()` will result in an error being thrown.
-- | ```
-- | updateStr dedecipher input inputEncoding outputEncoding
-- | ```
updateStrStr :: String -> Encoding -> Encoding -> Decipher -> Effect String
updateStrStr string inputEncoding outputEncoding dedecipher =
  runEffectFn4 updateStrStrImpl dedecipher string (encodingToNode inputEncoding) (encodingToNode outputEncoding)

