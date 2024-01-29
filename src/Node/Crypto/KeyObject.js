import * as crypto from "node:crypto";

export const eqKeyObjectImpl = (a, b) => a.equals(b);

export const newSecretKeyImpl = (buf) => crypto.newSecretKey(buf);
export const newPublicKeyBufImpl = (buf) => crypto.newPublicKey(buf);
export const newPublicKeyObjImpl = (obj) => crypto.newPublicKey(obj);
export const newPrivateKeyBufImpl = (buf) => crypto.newPrivateKey(buf);
export const newPrivateKeyObjImpl = (obj) => crypto.newPrivateKey(obj);

export const assymetricKeyDetails = (ko) => ko.assymetricKeyDetails;
export const assymetricKeyType = (ko) => ko.assymetricKeyType;
export const symmetricKeySize = (ko) => ko.symmetricKeySize;
export const typeImpl = (ko) => ko.type;
