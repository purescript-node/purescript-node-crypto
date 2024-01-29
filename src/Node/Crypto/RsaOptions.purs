-- | These constants are used in `Sign.sign` and `Verify.verify`.
module Node.Crypto.RsaOptions 
  ( SignPadding
  , rsa_pkcs1_padding
  , rsa_pkcs1_pss_padding
  , SaltLength
  , rsa_pss_saltlen_digest
  , rsa_pss_saltlen_max_sign
  ) where

import Prelude

newtype SignPadding = SignPadding Int

derive newtype instance Eq SignPadding
derive newtype instance Ord SignPadding
derive newtype instance Show SignPadding

foreign import js_rsa_pkcs1_padding :: Int
rsa_pkcs1_padding = SignPadding js_rsa_pkcs1_padding :: SignPadding

foreign import js_rsa_pkcs1_pss_padding :: Int
rsa_pkcs1_pss_padding = SignPadding js_rsa_pkcs1_pss_padding :: SignPadding

newtype SaltLength = SaltLength Int

derive newtype instance Eq SaltLength
derive newtype instance Ord SaltLength
derive newtype instance Show SaltLength

foreign import js_rsa_pss_saltlen_digest :: Int
rsa_pss_saltlen_digest = SaltLength js_rsa_pss_saltlen_digest :: SaltLength

foreign import js_rsa_pss_saltlen_max_sign :: Int
rsa_pss_saltlen_max_sign = SaltLength js_rsa_pss_saltlen_max_sign :: SaltLength
