// Cryptographic primitives the TCA runs in the browser: base64 and BLS12-381
// encoding helpers, PS signature verification, the client side of the PIN-OPRF,
// and AES-GCM protection of the authorization record.

import { bls, Ristretto255, sha512, hkdf } from './vendor/crypto-deps.js';

// Renders bytes as an uppercase 0x-prefixed hex string for display.
function prettyPrintBytes(bytes) {
  if (bytes == null) return '0x';
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return '0x' + hex;
}

// Encodes bytes as base64.
function uint8ArrayToBase64(u8) {
  if (!(u8 instanceof Uint8Array)) throw new TypeError('expected Uint8Array');

  let binary = '';
  const chunkSize = 8192;

  for (let i = 0; i < u8.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, u8.length);
    const chunk = u8.subarray(i, end);

    let chunkBinary = '';
    for (let j = 0; j < chunk.length; j++) {
      chunkBinary += String.fromCharCode(chunk[j]);
    }
    binary += chunkBinary;
  }
  
  return btoa(binary);
}

// Decodes a base64 string into bytes.
function base64ToUint8Array(b64) {
  if (typeof b64 !== 'string') throw new TypeError('expected base64 string');
  
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    
    return bytes;
  } catch (e) {
    throw new Error('Invalid base64 string: ' + (e.message || 'decode failed'));
  }
}

// Encodes bytes as the base64 string form used on the wire.
export function uint8ArrayToString(u8) {
    return uint8ArrayToBase64(u8);
}

// Decodes the base64 string form used on the wire back into bytes.
export function stringToUint8Array(str) {
    return base64ToUint8Array(str);
}

// The IdP's credential verification key, parsed into curve points.
export class PSPublicKey {
    constructor(Yn, Xhat, Yhatn) {
        this.Yn = Yn;
        this.Xhat = Xhat;
        this.Yhatn = Yhatn;
    }
    static fromJSON(obj) {
        const ynBytes = base64ToUint8Array(obj.yn[0]);
        const xhatBytes = base64ToUint8Array(obj.xhat);
        const yhatnBytes = base64ToUint8Array(obj.yhatn[0]);
        
        const Yn = bls.PointG1.fromHex(ynBytes);
        const Xhat = bls.PointG2.fromHex(xhatBytes);
        const Yhatn = bls.PointG2.fromHex(yhatnBytes);
        return new PSPublicKey(Yn, Xhat, Yhatn);
    }
}

// Order of the BLS12-381 scalar field.
const BLS_SCALAR_R = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

// Reads big-endian bytes as a BigInt.
function bytesToBigIntBE(bytes) {
  let hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  if (hex === '') return 0n;
  return BigInt('0x' + hex);
}

// Reduces bytes into a BLS12-381 scalar.
function bytesToScalarBigInt(bytes) {
  const n = bytesToBigIntBE(bytes);
  return n % BLS_SCALAR_R;
}

// Writes a non-negative BigInt as big-endian bytes, optionally padded to a fixed
// length.
function bigIntToUint8ArrayBE(n, length) {
  if (typeof n !== 'bigint') throw new TypeError('n must be BigInt');
  if (n < 0n) throw new RangeError('n must be non-negative');

  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const byteLen = hex.length / 2;
  const bytes = new Uint8Array(byteLen);
  for (let i = 0; i < byteLen; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  if (length !== undefined) {
    if (!Number.isInteger(length) || length < 0) throw new TypeError('length must be non-negative integer');
    if (byteLen > length) throw new RangeError('BigInt too large to fit in desired length');
    const out = new Uint8Array(length);
    out.set(bytes, length - byteLen);
    return out;
  }

  return bytes;
}

// Maps the wire string form of a value onto a BLS12-381 scalar.
export function stringToScalarBigInt(str) {
    const bytes = stringToUint8Array(str);
    return bytesToScalarBigInt(bytes);
}

// Encodes a scalar as its 32-byte wire string form.
export function bigIntToString(n) {
    const bytes = bigIntToUint8ArrayBE(n, 32);
    return uint8ArrayToString(bytes);
}

// Decodes the wire string form of a G1 point.
function stringToG1(str) {
    const strPoint = stringToUint8Array(str);
    return bls.PointG1.fromHex(strPoint);
}

// Returns the additive inverse of a scalar.
function negativeScalar(t) {
    return (BLS_SCALAR_R - t) % BLS_SCALAR_R;
}

// Verifies a randomized PS signature (acid) against the IdP's verification key,
// which is what lets the user confirm the RP's identity in the browser.
export function PSVerify(acid, domain, t, cvk) {
    let acidObj = JSON.parse(acid);

    const sigma1 = stringToG1(acidObj.Sigma1);
    const sigma2 = stringToG1(acidObj.Sigma2);
    let domainScalar = stringToScalarBigInt(domain);
    let tScalar = stringToScalarBigInt(t);
    let negT = negativeScalar(tScalar);
    
    const eqLeft = bls.pairing(sigma2.add(sigma1.multiply(negT)), bls.PointG2.BASE);
    const eqRight = bls.pairing(sigma1, cvk.Xhat.add(cvk.Yhatn.multiply(domainScalar)));
    return eqLeft.equals(eqRight);
}

// Blinds an input into a ristretto255 point, returning the serialized blinded
// point together with the blinding scalar.
async function clientBlind(inputBytes) {
  console.log('[DEBUG clientBlind] inputBytes length:', inputBytes.length);
  console.log('[DEBUG clientBlind] inputBytes (hex):', Array.from(inputBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  const P = Ristretto255.fromHash(inputBytes); // RistrettoPoint
  console.log('[DEBUG clientBlind] P (point):', P);
  
  const rBig = Ristretto255.scalar.getRandom();
  console.log('[DEBUG clientBlind] rBig (scalar):', rBig);
  console.log('[DEBUG clientBlind] rBig type:', typeof rBig);
  
  const B = Ristretto255.scalarMult(rBig, P);
  console.log('[DEBUG clientBlind] B (blinded point):', B);
  console.log('[DEBUG clientBlind] B type:', typeof B);
  console.log('[DEBUG clientBlind] B instanceof Uint8Array:', B instanceof Uint8Array);
  
  let B_bytes;
  if (B instanceof Uint8Array) {
    B_bytes = B;
    console.log('[DEBUG clientBlind] B is already Uint8Array, using directly');
  } else {
    B_bytes = Ristretto255.unsafe.point.toBytes(B);
    console.log('[DEBUG clientBlind] B is point object, calling toBytes');
  }
  
  console.log('[DEBUG clientBlind] B_bytes length:', B_bytes.length);
  console.log('[DEBUG clientBlind] B_bytes (hex):', Array.from(B_bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  console.log('[DEBUG clientBlind] B_bytes (base64 raw):', btoa(String.fromCharCode(...B_bytes)));
  
  const allZeros = Array.from(B_bytes).every(b => b === 0);
  console.log('[DEBUG clientBlind] B_bytes all zeros?', allZeros);
  if (allZeros) {
    console.error('[ERROR clientBlind] B_bytes is all zeros! This should not happen.');
  }
  
  return { B_bytes, rBig, P };
}

// Removes the blinding from the IdP's OPRF evaluation and hashes the result into
// the seed the PIN-bound key is derived from. It rejects any beta that is not a
// canonical group element, which would otherwise degrade into the identity and
// yield a key independent of the PIN.
async function clientUnblindAndFinalize(S_bytes, rBig) {
  if (!Ristretto255.isValid(S_bytes)) {
    throw new Error('OPRF unblind: beta is not a valid ristretto255 group element');
  }
  const rInv = Ristretto255.scalar.invert(rBig);
  const kP_bytes = Ristretto255.scalarMult(rInv, S_bytes);
  return sha512(kP_bytes);
}

// Derives an encryption key from input keying material with HKDF-SHA512.
function hkdfDeriveEncKey(ikm, salt = new Uint8Array(0), info = new Uint8Array(0), length = 32) {
  if (!(ikm instanceof Uint8Array)) throw new TypeError('ikm must be Uint8Array');
  if (!(salt instanceof Uint8Array)) throw new TypeError('salt must be Uint8Array');
  if (!(info instanceof Uint8Array)) throw new TypeError('info must be Uint8Array');
  if (!Number.isInteger(length) || length <= 0) throw new TypeError('length must be positive integer');

  return hkdf(sha512, ikm, salt, info, length);
}

// Concatenates two byte arrays.
export function CombineUint8Array(bytes1, bytes2) {
    if (!(bytes1 instanceof Uint8Array)) throw new TypeError('bytes1 must be Uint8Array');
    if (!(bytes2 instanceof Uint8Array)) throw new TypeError('bytes2 must be Uint8Array');
    const out = new Uint8Array(bytes1.length + bytes2.length);
    out.set(bytes1, 0);
    out.set(bytes2, bytes1.length);
    return out;
}

// Builds the blinded OPRF request alpha from the user's PIN and uid, returning it
// with the blinding scalar needed to unblind the IdP's answer.
export async function CreateRegistrationRequest(PIN, uid) {
  let PIN_bytes, uid_bytes;
  if (typeof PIN == 'string')
    PIN_bytes = new TextEncoder().encode(PIN);
  else if (PIN instanceof Uint8Array)
    PIN_bytes = PIN;
  else
    throw new TypeError('PIN must be string or Uint8Array');
  
  console.log('[DEBUG CreateRegistrationRequest] PIN_bytes length:', PIN_bytes.length);
  console.log('[DEBUG CreateRegistrationRequest] PIN_bytes (hex):', Array.from(PIN_bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  if (typeof uid == 'string')
    uid_bytes = new TextEncoder().encode(uid);
  else if (uid instanceof Uint8Array)
    uid_bytes = uid;
  else if (uid === null || uid === undefined) {
    console.error('[ERROR CreateRegistrationRequest] uid is null or undefined!');
    throw new TypeError('uid must be string or Uint8Array, but got: ' + typeof uid);
  } else {
    throw new TypeError('uid must be string or Uint8Array');
  }

  console.log('[DEBUG CreateRegistrationRequest] uid_bytes length:', uid_bytes.length);
  console.log('[DEBUG CreateRegistrationRequest] uid_bytes (hex):', Array.from(uid_bytes).map(b => b.toString(16).padStart(2, '0')).join(''));

  const combined = CombineUint8Array(PIN_bytes, uid_bytes);
  console.log('[DEBUG CreateRegistrationRequest] combined length:', combined.length);
  console.log('[DEBUG CreateRegistrationRequest] combined (hex):', Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  const inputBytes = sha512(combined);
  console.log('[DEBUG CreateRegistrationRequest] inputBytes (sha512) length:', inputBytes.length);
  console.log('[DEBUG CreateRegistrationRequest] inputBytes (sha512) (hex):', Array.from(inputBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  const { B_bytes, rBig, P } = await clientBlind(inputBytes);
  console.log('[DEBUG CreateRegistrationRequest] B_bytes length:', B_bytes.length);
  console.log('[DEBUG CreateRegistrationRequest] B_bytes (hex):', Array.from(B_bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  console.log('[DEBUG CreateRegistrationRequest] B_bytes (base64 raw):', btoa(String.fromCharCode(...B_bytes)));
  
  const alpha = uint8ArrayToString(B_bytes);
  console.log('[DEBUG CreateRegistrationRequest] alpha (final):', alpha);
  console.log('[DEBUG CreateRegistrationRequest] alpha length:', alpha.length);
  
  return { alpha, rBig };
}

// Turns the IdP's OPRF response into the PIN-bound encryption key K_m.
export async function GenerateEncKey(beta, r) {
    const beta_bytes = stringToUint8Array(beta);
    const seed = await clientUnblindAndFinalize(beta_bytes, r);
    return hkdfDeriveEncKey(seed);
}

// Encrypts under AES-GCM, returning the random IV alongside the ciphertext.
async function AES_GCM_Encrypt(enc_key, plaintext, associatedData = null) {
    if (!(enc_key instanceof Uint8Array)) throw new TypeError('enc_key must be Uint8Array');
  const cryptoKey = await crypto.subtle.importKey('raw', enc_key, 'AES-GCM', false, ['encrypt']);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  let pt;
  if (typeof plaintext === 'string') {
    pt = new TextEncoder().encode(plaintext);
  } else if (plaintext instanceof Uint8Array) {
    pt = plaintext;
  } else {
    throw new TypeError('plaintext must be string or Uint8Array');
  }

  const alg = { name: 'AES-GCM', iv: iv, tagLength: 128 };
  if (associatedData !== null) {
    alg.additionalData = (associatedData instanceof Uint8Array) 
      ? associatedData 
      : new TextEncoder().encode(String(associatedData));
  }

  const ctBuf = await crypto.subtle.encrypt(alg, cryptoKey, pt);
  const ctU8 = new Uint8Array(ctBuf);

  return {
    iv: iv,
    ciphertext: ctU8,
  };
}

// Decrypts an AES-GCM ciphertext, throwing if authentication fails.
async function AES_GCM_Decrypt(enc_key, iv, ciphertext, associatedData = null) {
    if (!(enc_key instanceof Uint8Array)) throw new TypeError('enc_key must be Uint8Array');

    let iv_bytes;
    if (typeof iv === 'string') {
        iv_bytes = stringToUint8Array(iv);
    } else if (iv instanceof Uint8Array) {
        iv_bytes = iv;
    } else {
        throw new TypeError('iv must be a base64 string or Uint8Array');
    }

    let ct_bytes;
    if (typeof ciphertext === 'string') {
        ct_bytes = stringToUint8Array(ciphertext);
    } else if (ciphertext instanceof Uint8Array) {
        ct_bytes = ciphertext;
    } else {
        throw new TypeError('ciphertext must be a base64 string or Uint8Array');
    }

    const cryptoKey = await crypto.subtle.importKey('raw', enc_key, 'AES-GCM', false, ['decrypt']);

    const alg = { name: 'AES-GCM', iv: iv_bytes, tagLength: 128 };
    if (associatedData !== null) {
        alg.additionalData = (associatedData instanceof Uint8Array)
            ? associatedData
            : new TextEncoder().encode(String(associatedData));
    }

    try {
        const ptBuf = await crypto.subtle.decrypt(alg, cryptoKey, ct_bytes);
        return new Uint8Array(ptBuf);
    } catch (e) {
        throw new Error('AES-GCM decryption failed: ' + (e && e.message ? e.message : String(e)));
    }
}

// Encrypts the authorization record (domain and acid) under K_m, returning the
// ciphertext and the nonce bound into it.
export async function GenerateDEnc(enc_key, D, acid) {
    let plaintext = "";
    plaintext += (typeof D === 'string') ? D + ':' : "";
    if (typeof acid === 'string') {
        let acidObj = JSON.parse(acid);
        plaintext += acidObj.Sigma1 + ':' + acidObj.Sigma2;
    } else {
        plaintext += "";
    }
    const nonce_bytes = crypto.getRandomValues(new Uint8Array(16));
    const plaintext_bytes = new TextEncoder().encode(plaintext);
    const { iv, ciphertext } = await AES_GCM_Encrypt(enc_key, CombineUint8Array(plaintext_bytes, nonce_bytes));
    const combined_bytes = CombineUint8Array(iv, ciphertext);
    const combined_b64 = uint8ArrayToString(combined_bytes);
    
    return {
        combined: combined_b64,
        nonce: uint8ArrayToString(nonce_bytes),
    };
}

// Decrypts an authorization record under K_m into its domain, acid and nonce.
// It accepts the record either as an {iv, ciphertext} object or as one combined
// base64 string.
export async function DecryptDEnc(enc_key, denc) {
    let iv_bytes, ct_bytes;

    if (typeof denc === 'object' && denc !== null) {
        if (typeof denc.iv !== 'string' || typeof denc.ciphertext !== 'string') {
            throw new TypeError('denc.iv and denc.ciphertext must be strings');
        }
        iv_bytes = stringToUint8Array(denc.iv);
        ct_bytes = stringToUint8Array(denc.ciphertext);
    } else if (typeof denc === 'string') {
        const combined_bytes = stringToUint8Array(denc);

        if (combined_bytes.length < 12) {
            throw new Error('Invalid denc: too short to contain IV');
        }
        
        iv_bytes = combined_bytes.subarray(0, 12);
        ct_bytes = combined_bytes.subarray(12);
    } else {
        throw new TypeError('denc must be an object {iv, ciphertext} or a string');
    }

    const result = await AES_GCM_Decrypt(enc_key, iv_bytes, ct_bytes);
    const result_str = new TextDecoder('ascii').decode(result.subarray(0, result.length - 16));
    console.log(`Decrypted DEnc result_str: ${result_str}`);
    const parts = result_str.split(':').filter(Boolean).map(part => part.replace(/:/g, ''));
    return {
        D: parts[0] || null,
        Sigma1: parts[1] || null,
        Sigma2: parts[2] || null,
        Nonce: prettyPrintBytes(result.subarray(result.length - 16)) || null,
    };
}

// Decodes a base64 string into UTF-8 text.
export function base64ToString(b64) {
  const bytes = base64ToUint8Array(b64);
  try {
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    throw new Error('UTF-8 decode failed: ' + (e && e.message ? e.message : String(e)));
  }
}