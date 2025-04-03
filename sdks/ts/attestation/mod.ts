import { decodeHex } from "jsr:@std/encoding@1/hex";
import { decode, encode } from "npm:cbor2@1";
import { X509Certificate } from "npm:@peculiar/x509@1";

// Graveyard of x509 libraries that did not work, fuck me I guess
//
// node:crypto - certificate verification not implemented in deno, will not work in a browser anyway
// node-forge - does not support ECC, only RSA
// @fidm/x509 - failed to parse dates
// pkijs - failed certificate chain verification

export const AWS_ROOT_KEY: Uint8Array = decodeHex(
  "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
);
export const MOCK_ROOT_KEY: Uint8Array = decodeHex(
  "6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410",
);

export interface AttestationDecoded {
  timestamp: number;
  pcrs: Uint8Array[];
  rootPublicKey: Uint8Array;
  publicKey: Uint8Array;
  userData: Uint8Array;
}

export class AttestationError extends Error {
  constructor(
    type: "ParseFailed" | "VerifyFailed" | "HttpClientError",
    message: string,
  ) {
    super(`${type}: ${message}`);
    this.name = "AttestationError";
  }
}

export interface AttestationExpectations {
  timestamp?: number;
  age?: {
    maxAge: number;
    currentTimestamp: number;
  };
  pcrs?: Uint8Array[];
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  rootPublicKey?: Uint8Array;
}

export async function verify(
  attestationDoc: Uint8Array,
  expectations: AttestationExpectations = {},
): Promise<AttestationDecoded> {
  const result: AttestationDecoded = {
    timestamp: 0,
    pcrs: Array(3).fill(new Uint8Array(48)),
    rootPublicKey: new Uint8Array(),
    publicKey: new Uint8Array(),
    userData: new Uint8Array(),
  };

  // parse attestation doc
  const [coseSign1, attestationData] = parseAttestationDoc(attestationDoc);

  // parse timestamp
  result.timestamp = parseTimestamp(attestationData);

  // check expected timestamp if exists
  if (
    expectations.timestamp &&
    result.timestamp !== expectations.timestamp
  ) {
    throw new AttestationError("VerifyFailed", "timestamp mismatch");
  }

  // check age if exists
  if (expectations.age) {
    const { maxAge, currentTimestamp } = expectations.age;
    if (
      result.timestamp <= currentTimestamp &&
      currentTimestamp - result.timestamp > maxAge
    ) {
      throw new AttestationError(
        "VerifyFailed",
        "too old",
      );
    }
  }

  // parse pcrs
  result.pcrs = parsePCRs(attestationData);

  // check pcrs if exists
  if (
    expectations.pcrs && !(
      result.pcrs.length === expectations.pcrs.length &&
      result.pcrs.every((pcr, i) =>
        pcr.toString() === expectations.pcrs![i].toString()
      )
    )
  ) {
    throw new AttestationError("VerifyFailed", "pcrs mismatch");
  }

  // verify signature and cert chain
  result.rootPublicKey = await verifyRootOfTrust(
    attestationData,
    coseSign1,
    result.timestamp,
  );

  // check root public key if exists
  if (
    expectations.rootPublicKey &&
    result.rootPublicKey.toString() !== expectations.rootPublicKey.toString()
  ) {
    throw new AttestationError("VerifyFailed", "root public key mismatch");
  }

  // return the enclave key
  result.publicKey = parseEnclaveKey(attestationData);

  // check enclave public key if exists
  if (
    expectations.publicKey &&
    result.publicKey.toString() !== expectations.publicKey.toString()
  ) {
    throw new AttestationError("VerifyFailed", "enclave public key mismatch");
  }

  // return the user data
  result.userData = parseUserData(attestationData);

  // check user data if exists
  if (
    expectations.userData &&
    result.userData.toString() !== expectations.userData.toString()
  ) {
    throw new AttestationError("VerifyFailed", "user data mismatch");
  }

  return result;
}

interface AttestationPayload {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  public_key: Uint8Array;
  user_data: Uint8Array;
  nonce: Uint8Array;
}

// deno-lint-ignore no-explicit-any
function isAttestationPayload(payload: any): payload is AttestationPayload {
  if (
    typeof payload === "object" && typeof payload.module_id === "string" &&
    typeof payload.digest === "string" &&
    typeof payload.timestamp === "number" &&
    payload.pcrs instanceof Map &&
    // deno-lint-ignore no-explicit-any
    payload.pcrs.keys().every((x: any) => typeof x === "number") &&
    // deno-lint-ignore no-explicit-any
    payload.pcrs.values().every((x: any) => x instanceof Uint8Array) &&
    payload.certificate instanceof Uint8Array &&
    Array.isArray(payload.cabundle) &&
    // deno-lint-ignore no-explicit-any
    payload.cabundle.every((x: any) => x instanceof Uint8Array) &&
    (payload.public_key === null || payload.public_key instanceof Uint8Array) &&
    (payload.user_data === null || payload.user_data instanceof Uint8Array) &&
    (payload.nonce === null || payload.nonce instanceof Uint8Array)
  ) {
    return true;
  }

  return false;
}

function parseAttestationDoc(
  attestationDoc: Uint8Array,
): [Uint8Array, AttestationPayload] {
  try {
    const decoded = decode(attestationDoc);
    if (!Array.isArray(decoded)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cose`,
      );
    }

    const payloadBytes = decoded[2];
    if (!(payloadBytes instanceof Uint8Array)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cose payload`,
      );
    }

    const payload = decode(payloadBytes);
    if (!isAttestationPayload(payload)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cbor`,
      );
    }

    return [attestationDoc, payload];
  } catch (error) {
    throw new AttestationError(
      "ParseFailed",
      `Failed to parse attestation document: ${error}`,
    );
  }
}

function parseTimestamp(data: AttestationPayload): number {
  const timestamp = data.timestamp;

  return timestamp;
}

function parsePCRs(data: AttestationPayload): Uint8Array[] {
  const pcrs = data.pcrs;

  const result: Uint8Array[] = [];
  for (let i = 0; i < 3; i++) {
    const pcr = pcrs.get(i);
    if (!pcr || pcr.length !== 48) {
      throw new AttestationError("ParseFailed", `Invalid PCR${i}`);
    }
    result.push(pcr);
  }
  return result;
}

async function verifyRootOfTrust(
  data: AttestationPayload,
  coseSign1: Uint8Array,
  timestamp: number,
): Promise<Uint8Array> {
  // verify attestation doc signature using the leaf certificate's public key
  const enclaveCertBytes = data.certificate;
  const leafCert = new X509Certificate(enclaveCertBytes);

  // Extract raw P-384 public key (x || y)
  // leafCert.publicKey.rawData contains ASN.1 encoded SubjectPublicKeyInfo.
  // For P-384, the raw key starts after a 24-byte prefix (including the 0x04 uncompressed point indicator).
  // However, WebCrypto's 'raw' import expects *just* the point for ECDSA.
  const pubkeyRaw = new Uint8Array(leafCert.publicKey.rawData.slice(24)); // Should be 96 bytes (48 x + 48 y)

  // Verify the COSE_Sign1 signature
  await verifyCoseSign1P384(coseSign1, pubkeyRaw);

  // verify certificate chain
  const caBundle = data.cabundle;
  const rootKey = verifyCertChain(
    leafCert,
    caBundle.map((x) => new X509Certificate(x)).reverse(),
    timestamp,
  );

  return rootKey;
}

async function verifyCertChain(
  leafCert: X509Certificate,
  caBundle: X509Certificate[],
  timestamp: number,
): Promise<Uint8Array> {
  try {
    const certs = [leafCert, ...caBundle];

    for (let i = 0; i < certs.length - 1; i++) {
      const current = certs[i];
      const issuer = certs[i + 1];

      if (
        !(await current.verify({
          publicKey: issuer.publicKey,
          signatureOnly: true,
        }))
      ) {
        throw new AttestationError(
          "VerifyFailed",
          `Invalid signature for certificate ${i}`,
        );
      }

      if (current.issuer !== issuer.subject) {
        throw new AttestationError(
          "VerifyFailed",
          `Invalid issuer for certificate ${i}`,
        );
      }

      const now = new Date(timestamp);
      if (
        now < current.notBefore || now > current.notAfter
      ) {
        throw new AttestationError(
          "VerifyFailed",
          `Certificate ${i} is not valid at current time`,
        );
      }
    }

    const rootCert = certs[certs.length - 1];

    return new Uint8Array(rootCert.publicKey.rawData.slice(24));
  } catch (error) {
    throw new AttestationError(
      "VerifyFailed",
      `Certificate chain verification failed: ${error}`,
    );
  }
}

function parseEnclaveKey(data: AttestationPayload): Uint8Array {
  const publicKey = data.public_key || new Uint8Array();

  return publicKey;
}

function parseUserData(data: AttestationPayload): Uint8Array {
  const userData = data.user_data || new Uint8Array();

  return userData;
}

/**
 * Verifies a COSE_Sign1 structure with an ES384 (P-384 ECDSA with SHA-384) signature.
 * @param coseSign1 The COSE_Sign1 structure as a Uint8Array.
 * @param publicKeyRaw The raw P-384 public key (x and y coordinates concatenated).
 * @throws {AttestationError} If verification fails or the algorithm is not ES384.
 */
async function verifyCoseSign1P384(
  coseSign1: Uint8Array,
  publicKeyRaw: Uint8Array, // Expecting 96 bytes (48 bytes x + 48 bytes y)
): Promise<void> {
  if (publicKeyRaw.length !== 96) {
    throw new AttestationError(
      "VerifyFailed",
      `Invalid P-384 public key length: ${publicKeyRaw.length}`,
    );
  }

  let decodedCose: unknown;
  try {
    decodedCose = decode(coseSign1);
  } catch (e) {
    throw new AttestationError("ParseFailed", `COSE_Sign1 decode error: ${e}`);
  }

  if (
    !Array.isArray(decodedCose) || decodedCose.length !== 4 ||
    !(decodedCose[0] instanceof Uint8Array) || // protected header bytes
    // decodedCose[1] is the unprotected header, not needed for verification
    !(decodedCose[2] instanceof Uint8Array) || // payload bytes
    !(decodedCose[3] instanceof Uint8Array) // signature bytes
  ) {
    throw new AttestationError(
      "ParseFailed",
      "Invalid COSE_Sign1 structure",
    );
  }

  const [protectedHeaderBytes, _, payloadBytes, signatureBytes] = decodedCose;

  let protectedHeaderMap: unknown;
  try {
    protectedHeaderMap = decode(protectedHeaderBytes);
  } catch (e) {
    throw new AttestationError(
      "ParseFailed",
      `Protected header decode error: ${e}`,
    );
  }

  if (!(protectedHeaderMap instanceof Map)) {
    throw new AttestationError(
      "ParseFailed",
      "Protected header is not a map",
    );
  }

  // Check algorithm - MUST be ES384 (alg ID -35)
  const alg = protectedHeaderMap.get(1); // COSE Header Parameter "alg"
  if (alg !== -35) {
    throw new AttestationError(
      "VerifyFailed",
      `Unsupported COSE algorithm: ${alg}. Only ES384 (-35) is supported.`,
    );
  }

  // Construct the Sig_structure: [context, protected_header_bytes, external_aad_bytes, payload_bytes]
  // Context is "Signature1" for COSE_Sign1
  // external_aad is empty (zero-length byte string)
  const sigStructure = [
    "Signature1",
    protectedHeaderBytes,
    new Uint8Array(), // external_aad
    payloadBytes,
  ];

  const dataToVerify = encode(sigStructure);

  // Import the public key for Web Crypto
  // Prepend 0x04 to indicate uncompressed format
  const uncompressedPublicKey = new Uint8Array(publicKeyRaw.length + 1);
  uncompressedPublicKey[0] = 0x04;
  uncompressedPublicKey.set(publicKeyRaw, 1);

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      uncompressedPublicKey,
      { name: "ECDSA", namedCurve: "P-384" },
      true, // extractable = false is generally recommended, but true is fine here
      ["verify"],
    );
  } catch (e) {
    throw new AttestationError(
      "VerifyFailed",
      `Failed to import public key: ${e}`,
    );
  }

  // Verify the signature
  let isValid: boolean;
  try {
    isValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      cryptoKey,
      signatureBytes,
      dataToVerify,
    );
  } catch (e) {
    throw new AttestationError(
      "VerifyFailed",
      `Web Crypto verification error: ${e}`,
    );
  }

  if (!isValid) {
    throw new AttestationError("VerifyFailed", "COSE_Sign1 signature invalid");
  }
}

export async function get(endpoint: string): Promise<Uint8Array> {
  try {
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    throw new AttestationError(
      "HttpClientError",
      `Failed to fetch attestation document: ${error}`,
    );
  }
}
