import {ec} from 'elliptic';
let ecc = new ec('secp256k1');
let key = null;

export function getKey() {
    return key;
}

export function generateKeyPair() {
    key = ecc.genKeyPair();
    return key;
}

export function signKey(msgHash) {
    return key.sign(msgHash);
}

export function verifySignature(msgHash, signature) {
    const derSign = signature.toDER();
    return key.verify(msgHash, derSign);
}
