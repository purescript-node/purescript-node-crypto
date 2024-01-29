import * as crypto from "node:crypto";

export const checkPrimeImpl = (buf, cb) => crypto.checkPrime(buf, cb);
export const checkPrimeOptsImpl = (buf, opts, cb) => crypto.checkPrime(buf, opts, cb);
export const checkPrimeSyncImpl = (buf) => crypto.checkPrimSync(buf);
export const checkPrimeSyncOptsImpl = (buf, opts) => crypto.checkPrimSync(buf, opts);
export const diffieHelmanImpl = (pair) => crypto.diffieHellman(pair);
export const generateKeyHmacImpl = (len, cb) => crypto.generateKey("hmac", len, cb);
export const generateKeyAesImpl = (len, cb) => crypto.generateKey("aes", len, cb);