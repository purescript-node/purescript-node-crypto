import * as crypto from "node:crypto";
import * as constants from "node:constants";

export const newFromPrimeImpl = (prime) => crypto.createDiffieHellman(prime);
export const newFromPrimeGeneratorBufImpl = (prime, generator) => crypto.createDiffieHellman(prime, generator);
export const newFromPrimeGeneratorNumImpl = (prime, generator) => crypto.createDiffieHellman(prime, generator);
export const newFromPrimeLengthImpl = (primeLength) => crypto.createDiffieHellman(primeLength);
export const newFromPrimeLengthGeneratorImpl = (primeLength, generator) => crypto.createDiffieHellman(primeLength, generator);

export const computeSecretImpl = (dh, buf) => dh.computeSecret(buf);
export const generateKeysImpl = (dh) => dh.generateKeys();
export const getGeneratorImpl = (dh) => dh.getGenerator();
export const getPrimeImpl = (dh) => dh.getPrime();
export const getPrivateKeyImpl = (dh) => dh.getPrivateKey();
export const getPublicKeyImpl = (dh) => dh.getPublicKey();
export const setPrivateKeyImpl = (dh, buf) => dh.setPrivateKey(buf);
export const setPublicKeyImpl = (dh, buf) => dh.setPublicKey(buf);
export const verifyErrorImpl = (dh) => dh.verifyError;

export const dh_check_p_not_safe_prime = consntants.DH_CHECK_P_NOT_SAFE_PRIME;
export const dh_check_p_not_prime = consntants.DH_CHECK_P_NOT_PRIME;
export const dh_unable_to_check_generator = consntants.DH_UNABLE_TO_CHECK_GENERATOR;
export const dh_not_suitable_generator = consntants.DH_NOT_SUITABLE_GENERATOR;