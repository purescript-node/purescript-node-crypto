module Node.Crypto.Hash 
  ( Hash
  , toDuplex
  , new
  , NewOptions
  , new'
  , copy
  , CopyOptions
  , copy'
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
import Prim.Row as Row
import Unsafe.Coerce (unsafeCoerce)

-- | The `Hash` class is a utility for creating hash digests of data. 
-- | It can be used in one of two ways:
-- | - As a stream that is both readable and writable, where data is written to produce a computed hash digest on the readable side, or
-- | - Using the `hash.update()` and `hash.digest()` methods to produce the computed hash.
foreign import data Hash :: Type

toDuplex :: Hash -> Duplex
toDuplex = unsafeCoerce

new :: String -> Effect Hash
new string = runEffectFn1 newImpl string

foreign import newImpl :: EffectFn1 (String) (Hash)

type NewOptions =
  ( outputLength :: Number
  )

new' :: forall r trash. Row.Union r trash NewOptions => String -> { | r } -> Effect Hash
new' string r =
  runEffectFn2 newOptsImpl string r

foreign import newOptsImpl :: forall r. EffectFn2 (String) ({ | r }) (Hash)

-- | Creates a new Hash object that contains a deep copy of the internal state of the current Hash object.
-- | 
-- | An error is thrown when an attempt is made to copy the 
-- | Hash object after its `hash.digest()` method has been called.
copy :: Hash -> Effect Hash
copy hash = runEffectFn1 copyImpl hash

foreign import copyImpl :: EffectFn1 (Hash) (Hash)

type CopyOptions =
  ( outputLength :: Number
  )

-- | Creates a new Hash object that contains a deep copy of the internal state of the current Hash object.
-- | 
-- | The optional `options` argument controls stream behavior. 
-- | For XOF hash functions such as 'shake256', the `outputLength` option 
-- | can be used to specify the desired output length in bytes.
-- | 
-- | An error is thrown when an attempt is made to copy the 
-- | Hash object after its `hash.digest()` method has been called.
copy' :: forall r trash. Row.Union r trash CopyOptions => { | r } -> Hash -> Effect Hash
copy' options hash = runEffectFn2 copyOptsImpl hash options

foreign import copyOptsImpl :: forall r. EffectFn2 (Hash) { | r } (Hash)

foreign import updateBufImpl :: EffectFn2 (Hash) (Buffer) (Unit)

-- | Updates the hash content with the given `Buffer` data.
-- | 
-- | This can be called many times with new data as it is streamed.
updateBuf :: Buffer -> Hash -> Effect Unit
updateBuf buffer hash =
  runEffectFn2 updateBufImpl hash buffer

foreign import updateStrImpl :: EffectFn3 (Hash) (String) (String) (Unit)

-- | Updates the hash content with the given `String` data that will be encoded via Encoding.
-- | 
-- | This can be called many times with new data as it is streamed.
updateStr :: Encoding -> String -> Hash -> Effect Unit
updateStr encoding string hash =
  runEffectFn3 updateStrImpl hash string (encodingToNode encoding)

foreign import digestBufImpl :: EffectFn1 (Hash) (Buffer)

-- | Calculates the digest of all of the data passed via the `hash.update()` method to be hashed.
-- | 
-- | The Hash object can NOT be used again after `hash.digest()` method has been called. Multiple calls will cause an error to be thrown.
digestBuf :: Hash -> Effect Buffer
digestBuf hash = runEffectFn1 digestBufImpl hash

foreign import digestStrImpl :: EffectFn2 (Hash) (String) (String)

-- | Calculates the digest of all of the data passed via the `hash.update()` method to be hashed.
-- | The `Encoding` arg specifies the encoding of the outputted `String`.
-- | 
-- | The Hash object can NOT be used again after `hash.digest()` method has been called. Multiple calls will cause an error to be thrown.
digestStr :: Encoding -> Hash -> Effect String
digestStr encoding hash =
  runEffectFn2 digestStrImpl hash (encodingToNode encoding)