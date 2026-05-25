const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encodes a byte array to base58 representation.
 */
export function encodeBase58(source: Uint8Array | number[]): string {
  if (source.length === 0) return "";
  const digits = [0];
  for (let i = 0; i < source.length; i++) {
    let carry = source[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let string = "";
  for (let k = 0; k < source.length && source[k] === 0; k++) {
    string += BASE58_ALPHABET[0];
  }
  for (let q = digits.length - 1; q >= 0; q--) {
    string += BASE58_ALPHABET[digits[q]];
  }
  return string;
}

/**
 * Formats an Ed25519 public key hex or byte array as a did:key identifier.
 */
export function toDIDKey(publicKey: string | Uint8Array): string {
  let bytes: Uint8Array;
  if (typeof publicKey === "string") {
    const cleanHex = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    bytes = new Uint8Array(cleanHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  } else {
    bytes = publicKey;
  }
  
  const multicodec = new Uint8Array(2 + bytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(bytes, 2);
  
  return `did:key:z${encodeBase58(multicodec)}`;
}

/**
 * Imports a raw 32-byte Ed25519 public key for use in subtle crypto.
 */
export async function importPublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    publicKey as any,
    { name: "Ed25519" },
    true,
    ["verify"]
  );
}

/**
 * Imports a raw 32-byte Ed25519 private key (using PKCS8 wrapping).
 */
export async function importPrivateKey(privateKey: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(16 + privateKey.length);
  pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20], 0);
  pkcs8.set(privateKey, 16);

  return await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as any,
    { name: "Ed25519" },
    true,
    ["sign"]
  );
}

/**
 * Signs data offline using Ed25519.
 */
export async function signEd25519(
  privateKey: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const key = await importPrivateKey(privateKey);
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, data as any);
  return new Uint8Array(signature);
}

/**
 * Verifies an Ed25519 signature.
 */
export async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  const key = await importPublicKey(publicKey);
  return await crypto.subtle.verify({ name: "Ed25519" }, key, signature as any, data as any);
}

export interface VerifiableCredential {
  "@context": string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: Record<string, any>;
  proof: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    jws: string;
  };
}

/**
 * Creates and signs a standard Verifiable Credential.
 */
export async function createVerifiableCredential(
  issuerDid: string,
  subjectDid: string,
  claims: Record<string, any>,
  privateKey: Uint8Array,
  types: string[] = ["VerifiableCredential"]
): Promise<VerifiableCredential> {
  const issuanceDate = new Date().toISOString();
  const credentialSubject = {
    id: subjectDid,
    ...claims
  };

  const doc = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: types,
    issuer: issuerDid,
    issuanceDate,
    credentialSubject
  };

  const serialized = JSON.stringify(doc);
  const data = new TextEncoder().encode(serialized);
  const signatureBytes = await signEd25519(privateKey, data);
  
  const jws = btoa(String.fromCharCode(...signatureBytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return {
    ...doc,
    proof: {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: `${issuerDid}#key-1`,
      proofPurpose: "assertionMethod",
      jws
    }
  };
}

/**
 * Offline verifies a Verifiable Credential using the issuer's public key.
 */
export async function verifyVerifiableCredential(
  vc: VerifiableCredential,
  issuerPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const docToVerify = {
      "@context": vc["@context"],
      type: vc.type,
      issuer: vc.issuer,
      issuanceDate: vc.issuanceDate,
      credentialSubject: vc.credentialSubject
    };

    const serialized = JSON.stringify(docToVerify);
    const data = new TextEncoder().encode(serialized);

    const jws = vc.proof.jws;
    let base64 = jws.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    const signatureBytes = new Uint8Array(
      atob(base64)
        .split("")
        .map(char => char.charCodeAt(0))
    );

    return await verifyEd25519(issuerPublicKey, signatureBytes, data);
  } catch (e) {
    console.error("VC verification failed:", e);
    return false;
  }
}
