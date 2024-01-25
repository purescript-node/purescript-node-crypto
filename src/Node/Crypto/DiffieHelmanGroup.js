import * as crypto from "node:crypto";

export const newImpl = (groupName) => crypto.getDiffieHellman(groupName);

export const computeSecretImpl = (dh, buf) => dh.computeSecret(buf);
export const generateKeysImpl = (dh) => dh.generateKeys();
export const getGeneratorImpl = (dh) => dh.getGenerator();
export const getPrimeImpl = (dh) => dh.getPrime();
export const getPrivateKeyImpl = (dh) => dh.getPrivateKey();
export const getPublicKeyImpl = (dh) => dh.getPublicKey();
