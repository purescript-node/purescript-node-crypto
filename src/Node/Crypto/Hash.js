import * as crypto from "node:crypto";

export const newImpl = (algorithm) => crypto.createHash(algorithm);
export const newOptsImpl = (algorithm, opts) => crypto.createHash(algorithm, opts);
export const copyImpl = (hash) => hash.copy();
export const copyOptsImpl = (hash, opts) => hash.copy(opts);
export const updateBufImpl = (hash, buf) => hash.update(buf);
export const updateStrImpl = (hash, str, encoding) => hash.update(str, encoding);
export const digestBufImpl = (hash) => hash.digest();
export const digestStrImpl = (hash, encoding) => hash.digest(encoding);