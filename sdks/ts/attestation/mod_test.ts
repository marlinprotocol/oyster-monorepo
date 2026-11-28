import { assertEquals, assertRejects } from "jsr:@std/assert";
import { decodeHex } from "jsr:@std/encoding@1/hex";
import {
  AttestationError,
  AWS_ROOT_KEY,
  MOCK_ROOT_KEY,
  verify,
  verifyAnyRoot,
} from "./mod.ts";

// generated using `curl <ip>:<port>/attestation/raw`
// on the attestation server of a real Nitro enclave
Deno.test(async function testVerifyAWSNoneSpecified() {
  const attestation = await Deno.readFile(
    new URL("./testcases/aws.bin", import.meta.url),
  );

  const decoded = await verify(attestation);

  assertEquals(decoded.timestamp, 0x00000193bef3f3b0);
  assertEquals(
    decoded.pcrs[0],
    decodeHex(
      "189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6",
    ),
  );
  assertEquals(
    decoded.pcrs[1],
    decodeHex(
      "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16",
    ),
  );
  assertEquals(
    decoded.pcrs[2],
    decodeHex(
      "6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa",
    ),
  );
  assertEquals(
    decoded.userData,
    new Uint8Array(),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex(
      "e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb",
    ),
  );
  assertEquals(
    decoded.rootPublicKey,
    AWS_ROOT_KEY,
  );
});

// generated using `curl <ip>:<port>/attestation/raw`
// on the attestation server of a real Nitro enclave
Deno.test(async function testVerifyAWSAllSpecified() {
  const attestation = await Deno.readFile(
    new URL("./testcases/aws.bin", import.meta.url),
  );

  const decoded = await verify(attestation, {
    timestamp: 0x00000193bef3f3b0,
    age: {
      maxAge: 300000,
      currentTimestamp: 0x00000193bef3f3b0 + 300000,
    },
    pcrs: [
      decodeHex(
        "189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6",
      ),
      decodeHex(
        "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16",
      ),
      decodeHex(
        "6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa",
      ),
    ],
    publicKey: decodeHex(
      "e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb",
    ),
    userData: new Uint8Array(),
    rootPublicKey: AWS_ROOT_KEY,
  });

  assertEquals(decoded.timestamp, 0x00000193bef3f3b0);
  assertEquals(
    decoded.pcrs[0],
    decodeHex(
      "189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6",
    ),
  );
  assertEquals(
    decoded.pcrs[1],
    decodeHex(
      "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16",
    ),
  );
  assertEquals(
    decoded.pcrs[2],
    decodeHex(
      "6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa",
    ),
  );
  assertEquals(
    decoded.userData,
    new Uint8Array(),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex(
      "e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb",
    ),
  );
  assertEquals(
    decoded.rootPublicKey,
    AWS_ROOT_KEY,
  );
});

Deno.test(async function testVerifyMockRejectedUnlessAskedFor() {
  const attestation = await Deno.readFile(
    new URL("./testcases/custom.bin", import.meta.url),
  );

  // nothing specified means the aws root
  await assertRejects(
    () => verify(attestation),
    AttestationError,
    "root public key mismatch",
  );
  await assertRejects(
    () => verify(attestation, { publicKey: decodeHex("12345678") }),
    AttestationError,
    "root public key mismatch",
  );

  // an explicit root still works with both
  for (const f of [verify, verifyAnyRoot]) {
    await f(attestation, { rootPublicKey: MOCK_ROOT_KEY });
    await assertRejects(
      () => f(attestation, { rootPublicKey: AWS_ROOT_KEY }),
      AttestationError,
      "root public key mismatch",
    );
  }
});

Deno.test(async function testVerifyAWSAcceptedByDefault() {
  const attestation = await Deno.readFile(
    new URL("./testcases/aws.bin", import.meta.url),
  );

  assertEquals((await verify(attestation)).rootPublicKey, AWS_ROOT_KEY);
  assertEquals((await verifyAnyRoot(attestation)).rootPublicKey, AWS_ROOT_KEY);
  await assertRejects(
    () => verifyAnyRoot(attestation, { rootPublicKey: MOCK_ROOT_KEY }),
    AttestationError,
    "root public key mismatch",
  );
});

Deno.test(async function testVerifyAge() {
  const attestation = await Deno.readFile(
    new URL("./testcases/aws.bin", import.meta.url),
  );
  const timestamp = 0x00000193bef3f3b0;
  const check = (maxAge: number, currentTimestamp: number) =>
    verify(attestation, { age: { maxAge, currentTimestamp } });

  // within max age on either side
  await check(300000, timestamp);
  await check(300000, timestamp + 300000);
  await check(300000, timestamp - 300000);

  await assertRejects(
    () => check(300000, timestamp + 300001),
    AttestationError,
    "too old",
  );
  // used to pass, any timestamp ahead of the current one did
  await assertRejects(
    () => check(300000, timestamp - 300001),
    AttestationError,
    "timestamp too far in the future",
  );
  await assertRejects(
    () => check(300000, 0),
    AttestationError,
    "timestamp too far in the future",
  );
});

// generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
// on a custom mock attestation server running locally
Deno.test(async function testVerifyMockNoneSpecified() {
  const attestation = await Deno.readFile(
    new URL("./testcases/custom.bin", import.meta.url),
  );

  const decoded = await verifyAnyRoot(attestation);

  assertEquals(decoded.timestamp, 0x00000193bf444e30);
  assertEquals(decoded.pcrs[0], new Uint8Array(48).fill(0));
  assertEquals(decoded.pcrs[1], new Uint8Array(48).fill(1));
  assertEquals(decoded.pcrs[2], new Uint8Array(48).fill(2));
  assertEquals(
    decoded.userData,
    decodeHex("abcdef"),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex("12345678"),
  );
  assertEquals(
    decoded.rootPublicKey,
    MOCK_ROOT_KEY,
  );
});

// generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
// on a custom mock attestation server running locally
Deno.test(async function testVerifyMockAllSpecified() {
  const attestation = await Deno.readFile(
    new URL("./testcases/custom.bin", import.meta.url),
  );

  const decoded = await verify(attestation, {
    timestamp: 0x00000193bf444e30,
    age: {
      maxAge: 300000,
      currentTimestamp: 0x00000193bf444e30 + 300000,
    },
    pcrs: [
      new Uint8Array(48).fill(0),
      new Uint8Array(48).fill(1),
      new Uint8Array(48).fill(2),
    ],
    publicKey: decodeHex(
      "12345678",
    ),
    userData: decodeHex(
      "abcdef",
    ),
    rootPublicKey: MOCK_ROOT_KEY,
  });

  assertEquals(decoded.timestamp, 0x00000193bf444e30);
  assertEquals(decoded.pcrs[0], new Uint8Array(48).fill(0));
  assertEquals(decoded.pcrs[1], new Uint8Array(48).fill(1));
  assertEquals(decoded.pcrs[2], new Uint8Array(48).fill(2));
  assertEquals(
    decoded.userData,
    decodeHex("abcdef"),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex("12345678"),
  );
  assertEquals(
    decoded.rootPublicKey,
    MOCK_ROOT_KEY,
  );
});
