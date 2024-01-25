import * as crypto from "node:crypto";

export const newImpl = (algorithm, key) => crypto.createHmac(algorithm, key);
export const updateBufImpl = (hmac, buf) => hmac.update(buf);
export const updateStrImpl = (hmac, str, encoding) => hmac.update(str, encoding);
export const digestBufImpl = (hmac) => hmac.digest();
export const digestStrImpl = (hmac, encoding) => hmac.digest(encoding);