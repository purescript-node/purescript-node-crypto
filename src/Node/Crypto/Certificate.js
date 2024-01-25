import { Certificate } from "node:crypto";

export const exportChallengeImpl = (spkac) => Certificate.exportChallenge(spkac);
export const exportChallengeEncodingImpl = (spkac, encoding) => Certificate.exportChallenge(spkac, encoding);

export const exportPublicKeyImpl = (spkac) => Certificate.exportPublicKey(spkac);
export const exportPublicKeyEncodingImpl = (spkac, encoding) => Certificate.exportPublicKey(spkac, encoding);

export const verifySpkacImpl = (spkac) => Certificate.verifySpkac(spkac);
export const verifySpkacEncodingImpl = (spkac, encoding) => Certificate.verifySpkac(spkac, encoding);