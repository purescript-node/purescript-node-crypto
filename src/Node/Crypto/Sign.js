import * as crypto from "node:crypto";

export const newImpl = (algorithm) => crypto.createSign(algorithm);
export const updateBufImpl = (sign, key) => sign.update(key);
export const updateStrImpl = (sign, key, enc) => sign.update(key, enc);
export const signKeyObjectImpl = (sign, keyObj) => sign.sign(keyObj);
export const signObjImpl = (sign, obj) => sign.sign(obj);
