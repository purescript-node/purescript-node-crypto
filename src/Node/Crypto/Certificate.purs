-- | SPKAC is a Certificate Signing Request mechanism originally implemented by Netscape and was specified formally as part of HTML5's `keygen` element.
-- | 
-- | `<keygen>` is deprecated since [HTML 5.2](https://www.w3.org/TR/html52/changes.html#features-removed) and new projects should not use this element anymore.
-- | 
-- | The node:crypto module provides the Certificate class for working with SPKAC data. 
-- | The most common usage is handling output generated by the HTML5 <keygen> element. 
-- | Node.js uses [OpenSSL's SPKAC implementation](https://www.openssl.org/docs/man3.0/man1/openssl-spkac.html) internally.
module Node.Crypto.Certificate where

import Effect (Effect)
import Effect.Uncurried (EffectFn1, EffectFn2, runEffectFn1, runEffectFn2)
import Node.Buffer (Buffer)
import Node.Encoding (Encoding, encodingToNode)

foreign import exportChallengeImpl :: EffectFn1 (Buffer) (Buffer)

-- | Returns the challenge component of the spkac data structure, which includes a public key and a challenge.
exportChallenge :: Buffer -> Effect Buffer
exportChallenge buffer = runEffectFn1 exportChallengeImpl buffer

foreign import exportChallengeEncodingImpl :: EffectFn2 (String) (String) (Buffer)

-- | Returns the challenge component of the spkac data structure, which includes a public key and a challenge.
exportChallenge' :: String -> Encoding -> Effect Buffer
exportChallenge' str encoding =
  runEffectFn2 exportChallengeEncodingImpl str (encodingToNode encoding)

foreign import exportPublicKeyImpl :: EffectFn1 (Buffer) (Buffer)

-- | Returns the public key component of the spkac data structure, which includes a public key and a challenge.
exportPublicKey :: Buffer -> Effect Buffer
exportPublicKey buffer = runEffectFn1 exportPublicKeyImpl buffer

foreign import exportPublicKeyEncodingImpl :: EffectFn2 (String) (String) (Buffer)

-- | Returns the public key component of the spkac data structure, which includes a public key and a challenge.
exportPublicKey' :: String -> Encoding -> Effect Buffer
exportPublicKey' str encoding =
  runEffectFn2 exportPublicKeyEncodingImpl str (encodingToNode encoding)

foreign import verifySpkacImpl :: EffectFn1 (Buffer) (Boolean)

-- | Returns `true` if the given spkac data structure is valid, `false` otherwise.
verifySpkac :: Buffer -> Effect Boolean
verifySpkac buffer = runEffectFn1 verifySpkacImpl buffer

foreign import verifySpkacEncodingImpl :: EffectFn2 (String) (String) (Boolean)

-- | Returns `true` if the given spkac data structure is valid, `false` otherwise.
verifySpkac' :: String -> Encoding -> Effect Boolean
verifySpkac' str encoding =
  runEffectFn2 verifySpkacEncodingImpl str (encodingToNode encoding)



