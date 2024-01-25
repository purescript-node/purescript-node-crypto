import * as crypto from "node:crypto"

export const newImpl = (curveName) => crypto.createECDH(curveName);

export const convertKeyImpl = (key, curve) => crypto.ECDH.convertKey(key, curve);
export const convertKeyFormatImpl = (key, curve, format) => crypto.ECDH.convertKey(key, curve, undefined, undefined, format);
export const computeSecretImpl = (ecdh, otherPublicKey) => ecdh.computeSecret(otherPublicKey);
export const generateKeysImpl = (ecdh) => ecdh.generateKeys();
export const generateKeysFormatImpl = (ecdh, format) => ecdh.generateKeys(undefined, format);
export const getPrivateKeyImpl = (ecdh) => ecdh.getPrivateKey();
export const getPublicKeyImpl = (ecdh) => ecdh.getPublicKey();
export const getPublicKeyFormatImpl = (ecdh, format) => ecdh.getPublicKey(undefined, format);
export const setPrivateKeyImpl = (ecdh, key) => ecdh.setPrivateKey(key);

export const getCurves = () => crypto.getCurves();

export const errorCodeIsInvalidPublicKey = (err) => {
  if (err && err.code) {
    return err.code === "ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY";
  }
  return false;
}