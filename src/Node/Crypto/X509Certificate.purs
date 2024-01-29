module Node.Crypto.X509Certificate 
  ( X509Certificate
  , new
  , ca
  , checkEmail
  , checkEmail'
  , Subject -- constructor intentionally not exporte
  , defaultSubject
  , alwaysSubject
  , neverSubject
  , checkHost
  , checkHost'
  , CheckHostOptions
  , checkIP
  , checkIssued
  , checkPrivateKey
  , fingerprint
  , fingerprint256
  , fingerprint512
  , infoAccess
  , issuer
  , issuerCertificate
  , extKeyUsage
  , publicKey
  , raw
  , serialNumber
  , subject
  , subjectAltName
  , toJSONJs
  , toLegacyObjectJs
  , toStringJs
  , validFrom
  , validTo
  , verify
  ) where

import Prelude

import Data.Function.Uncurried (Fn1, Fn2, Fn3, runFn1, runFn2, runFn3)
import Data.Maybe (Maybe)
import Data.Nullable (Nullable, toMaybe)
import Foreign (Foreign)
import Node.Buffer (Buffer)
import Node.Crypto.KeyObject (Asymmetric, KeyObject, Private, Public)
import Prim.Row as Row

-- | Encapsulates an X509 certificate and provides read-only access to its information.
foreign import data X509Certificate :: Type

foreign import newImpl :: Fn1 (Buffer) (X509Certificate)

-- | Returns an `X509Certificate` given a PEM or DER encoded X509 Certificate.
new :: Buffer ->  X509Certificate
new buffer = runFn1 newImpl buffer

-- | Return `true` if this is a Certificate Authority (CA) certificate.
foreign import ca :: X509Certificate -> Boolean

foreign import checkEmailImpl :: Fn2 (X509Certificate) (String) (Maybe String)

-- | Checks whether the certificate matches the given email address.
-- | The certificate subject is only considered if the subject alternative name extension either does not exist or does not contain any email addresses.
-- | 
-- | - If the 'subject' option is `undefined` or set to `'default'`, the certificate subject is only considered if the subject alternative name extension either does not exist or does not contain any email addresses.
-- | - If the 'subject' option is set to `'always'` and if the subject alternative name extension either does not exist or does not contain a matching email address, the certificate subject is considered.
-- | - If the 'subject' option is set to `'never'`, the certificate subject is never considered, even if the certificate contains no subject alternative names.
checkEmail :: String -> X509Certificate ->  (Maybe String)
checkEmail email x509Certificate =
  runFn2 checkEmailImpl x509Certificate email

foreign import checkEmailOptsImpl :: Fn3 (X509Certificate) (String) { subject :: String} (Nullable String)

-- | Checks whether the certificate matches the given email address.
-- | - If the 'subject' option is `undefined` or set to `'default'`, the certificate subject is only considered if the subject alternative name extension either does not exist or does not contain any email addresses.
-- | - If the 'subject' option is set to `'always'` and if the subject alternative name extension either does not exist or does not contain a matching email address, the certificate subject is considered.
-- | - If the 'subject' option is set to `'never'`, the certificate subject is never considered, even if the certificate contains no subject alternative names.

checkEmail' :: String -> Subject -> X509Certificate ->  (Maybe String)
checkEmail' email (Subject subjectStr) x509Certificate =
  toMaybe $ runFn3 checkEmailOptsImpl x509Certificate email { subject: subjectStr }

newtype Subject = Subject String
derive newtype instance Eq Subject
derive newtype instance Ord Subject
derive newtype instance Show Subject

defaultSubject = Subject "default" :: Subject
alwaysSubject = Subject "always" :: Subject
neverSubject = Subject "never" :: Subject

foreign import checkHostImpl :: Fn2 (X509Certificate) (String) (Nullable String)

-- | Checks whether the certificate matches the given host name.
-- | 
-- | If the certificate matches the given host name, the matching subject name is returned. 
-- | The returned name might be an exact match (e.g., foo.example.com) or it might contain 
-- | wildcards (e.g., *.example.com). Because host name comparisons are case-insensitive, 
-- | the returned subject name might also differ from the given name in capitalization.
-- | 
-- | The certificate subject is only considered if the subject alternative name extension either does not exist or does not contain any DNS names. This behavior is consistent with RFC 2818 ("HTTP Over TLS").
checkHost :: String -> X509Certificate -> (Maybe String)
checkHost name cert=
  toMaybe $ runFn2 checkHostImpl cert name

foreign import checkHostOptsImpl :: forall r. Fn3 (X509Certificate) (String) ({ | r }) (Nullable String)

-- | Checks whether the certificate matches the given host name.
-- | 
-- | If the certificate matches the given host name, the matching subject name is returned. 
-- | The returned name might be an exact match (e.g., foo.example.com) or it might contain 
-- | wildcards (e.g., *.example.com). Because host name comparisons are case-insensitive, 
-- | the returned subject name might also differ from the given name in capitalization.
-- | 
-- | - If the 'subject' option is `undefined` or set to `'default'`, the certificate subject is only considered if the subject alternative name extension either does not exist or does not contain any DNS names. This behavior is consistent with RFC 2818 ("HTTP Over TLS").
-- | - If the 'subject' option is set to `'always'` and if the subject alternative name extension either does not exist or does not contain a matching DNS name, the certificate subject is considered.
-- | - If the 'subject' option is set to `'never'`, the certificate subject is never considered, even if the certificate contains no subject alternative names.
checkHost' :: forall r trash. Row.Union r trash CheckHostOptions => String -> { | r } -> X509Certificate -> (Maybe String)
checkHost' name opts cert =
  toMaybe $ runFn3 checkHostOptsImpl cert name opts   

type CheckHostOptions =
  ( subject :: Subject
  , wildcards :: Boolean
  , partialWildcards :: Boolean
  , multiLabelWildcards :: Boolean
  , singleLabelSubdomains :: Boolean
  )

foreign import checkIPImpl :: Fn2 (X509Certificate) (String) (Nullable String)

-- | Checks whether the certificate matches the given IP address (IPv4 or IPv6).
-- | Returns `Just ip` if the certificate matches, `Nothing` if it does not.
-- | 
-- | Only [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.txt) `iPAddress` 
-- | subject alternative names are considered, and they must match the given 
-- | ip address exactly. Other subject alternative names as well as the subject 
-- | field of the certificate are ignored.
checkIP :: String -> X509Certificate -> Maybe String
checkIP ip cert =
  toMaybe $ runFn2 checkIPImpl cert ip

foreign import checkIssuedImpl :: Fn2 (X509Certificate) (X509Certificate) (Boolean)

-- | Checks whether this certificate was issued by the given otherCert.
-- |
-- | ```
-- | thisCert # checkIssued otherCert
-- | checkIssued otherCert thisCert
-- | ```
checkIssued :: X509Certificate -> X509Certificate -> Boolean
checkIssued otherCert thisCert =
  runFn2 checkIssuedImpl thisCert otherCert

foreign import checkPrivateKeyImpl :: Fn2 (X509Certificate) (KeyObject (Asymmetric Private)) (Boolean)

checkPrivateKey :: KeyObject (Asymmetric Private) -> X509Certificate -> Boolean
checkPrivateKey keyObject x509Certificate =
  runFn2 checkPrivateKeyImpl x509Certificate keyObject 

-- | The SHA-1 fingerprint of this certificate.
-- | 
-- | Because SHA-1 is cryptographically broken and because the security of SHA-1 is significantly worse than that of algorithms that are commonly used to sign certificates, consider using x509.fingerprint256 instead.
foreign import fingerprint :: X509Certificate -> String

-- | The SHA-256 fingerprint of this certificate.
foreign import fingerprint256 :: X509Certificate -> String

-- | The SHA-512 fingerprint of this certificate.
-- | Because computing the SHA-256 fingerprint is usually faster and because it is only half the size of the SHA-512 fingerprint, x509.fingerprint256 may be a better choice. While SHA-512 presumably provides a higher level of security in general, the security of SHA-256 matches that of most algorithms that are commonly used to sign certificates.
foreign import fingerprint512 :: X509Certificate -> String

-- | A textual representation of the certificate's authority information access extension.
-- | 
-- | This is a line feed separated list of access descriptions. Each line begins with the access method and the kind of the access location, followed by a colon and the value associated with the access location.
-- | 
-- | After the prefix denoting the access method and the kind of the access location, the remainder of each line might be enclosed in quotes to indicate that the value is a JSON string literal. For backward compatibility, Node.js only uses JSON string literals within this property when necessary to avoid ambiguity. Third-party code should be prepared to handle both possible entry formats.
foreign import infoAccess :: X509Certificate -> String

-- | The issuer identification included in this certificate.
foreign import issuer :: X509Certificate -> String

-- | The issuer certificate or undefined if the issuer certificate is not available.
foreign import issuerCertificateImpl :: Fn1 X509Certificate (Nullable X509Certificate)

-- | The issuer certificate if it is available.
issuerCertificate :: X509Certificate -> Maybe X509Certificate
issuerCertificate cert = toMaybe $ runFn1 issuerCertificateImpl cert

-- | An array detailing the key extended usages for this certificate.
foreign import extKeyUsage :: X509Certificate -> Array String

-- | The public key <KeyObject> for this certificate.
foreign import publicKey :: X509Certificate -> KeyObject (Asymmetric Public)

-- | A Buffer containing the DER encoding of this certificate.
foreign import raw :: X509Certificate -> Buffer

-- | The serial number of this certificate.
-- | Serial numbers are assigned by certificate authorities and do not uniquely identify certificates. 
-- | Consider using `x509.fingerprint256` as a unique identifier instead.
foreign import serialNumber :: X509Certificate -> String

-- | The complete subject of this certificate.
foreign import subject :: X509Certificate -> String

-- | The subject alternative name specified for this certificate.
-- | 
-- | This is a comma-separated list of subject alternative names. Each entry begins with a string identifying the kind of the subject alternative name followed by a colon and the value associated with the entry.
-- | 
-- | Earlier versions of Node.js incorrectly assumed that it is safe to split this property at the two-character sequence ', ' (see CVE-2021-44532). However, both malicious and legitimate certificates can contain subject alternative names that include this sequence when represented as a string.
-- | 
-- | After the prefix denoting the type of the entry, the remainder of each entry might be enclosed in quotes to indicate that the value is a JSON string literal. For backward compatibility, Node.js only uses JSON string literals within this property when necessary to avoid ambiguity. Third-party code should be prepared to handle both possible entry formats.
foreign import subjectAltName :: X509Certificate -> String

-- | There is no standard JSON encoding for X509 certificates. The toJSON() method returns a string containing the PEM encoded certificate.
foreign import toJSONJs :: X509Certificate -> String

-- | Returns information about this certificate using the legacy certificate object encoding.
foreign import toLegacyObjectJs :: X509Certificate -> Foreign

-- | Returns the PEM-encoded certificate.
foreign import toStringJs :: X509Certificate -> String

-- | The date/time from which this certificate is valid.
foreign import validFrom :: X509Certificate -> String

-- | The date/time until which this certificate is valid.
foreign import validTo :: X509Certificate -> String

foreign import verifyImpl :: Fn2 (X509Certificate) (KeyObject (Asymmetric Public)) (Boolean)

-- | Verifies that this certificate was signed by the given public key. Does not perform any other validation checks on the certificate.
verify :: KeyObject (Asymmetric Public) -> X509Certificate -> Boolean
verify keyObject x509Certificate =
  runFn2 verifyImpl x509Certificate keyObject







