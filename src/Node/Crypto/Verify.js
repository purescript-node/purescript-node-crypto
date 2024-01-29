import * as crypto from "node:crypto";

export const newImpl = (algorithm) => crypto.createVerify(algorithm);
export const updateBufImpl = (verify, buf) => verify.update(buf);
export const updateStrImpl = (verify, str, enc) => verify.update(str, enc);
export const verifyKeyObjectImpl = (verify, keyObject, sig) => verify.verify(keyObject, sig);
export const verifyObjImpl = (verify, obj, sig) => verify.verify(obj, sig);