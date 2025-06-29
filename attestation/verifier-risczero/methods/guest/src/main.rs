use risc0_zkvm::guest::env;

use std::io::Read;

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::Signature;
use p384::ecdsa::VerifyingKey;
use sha2::Digest;
use sha2::Sha256;
use x509_cert::der::Decode;

// Design notes:
// Generally, it asserts a specific structure instead of parsing everything in a generic fashion.
// Helps keep the proving time low at the cost of being less flexible towards structure changes.
// Skips processing certificate extensions and subject/issuers. Verifies only signatures, expiry.

fn main() {
    // read the attestation
    let mut attestation = Vec::<u8>::new();
    env::stdin().read_to_end(&mut attestation).unwrap();

    println!(
        "Attestation: {} bytes: {:?}",
        attestation.len(),
        attestation
    );

    verify(&attestation, env::commit_slice);

    println!("Done!");
}

fn verify(attestation: &[u8], commit_slice: impl Fn(&[u8])) {
    // assert initial fields
    assert_eq!(
        attestation[0..8],
        [
            0x84, // the COSE structure is an array of size 4
            0x44, 0xa1, 0x01, 0x38, 0x22, // protected header, specifying P384 signature
            0xa0, // empty unprotected header
            0x59, // payload size of 2 bytes follows
        ]
    );

    // get payload size
    let payload_size = u16::from_be_bytes([attestation[8], attestation[9]]) as usize;
    println!("Payload size: {payload_size}");

    // assert total size
    assert_eq!(attestation.len(), 10 + payload_size + 98);

    // payload should be in attestation[10..10 + payload_size]
    // signature should be in attestation[12 + payload_size..108 + payload_size]

    // attestation doc payload is map of size at least 8
    // expected keys: module_id, digest, timestamp, pcrs, certificate, cabundle,
    // public_key, user_data
    assert!(attestation[10] >= 0xa9 && attestation[10] <= 0xbf);

    // skip fields and simply assert length
    assert_eq!(attestation[11], 0x69); // text of size 9, "module_id" key
    assert_eq!(attestation[21], 0x78); // text with one byte length follows

    // skip to after the module id
    let mut offset = 23 + attestation[22] as usize;

    assert_eq!(attestation[offset], 0x66); // text of size 6, "digest" key
    assert_eq!(attestation[offset + 7], 0x66); // text of size 6, "SHA384" value

    // assert timestamp key
    assert_eq!(attestation[offset + 14], 0x69); // text of size 9
    assert_eq!(&attestation[offset + 15..offset + 24], b"timestamp");
    // commit the timestamp value
    assert_eq!(attestation[offset + 24], 0x1b); // unsigned int, size 8
    println!("Timestamp: {:?}", &attestation[offset + 25..offset + 33]);
    commit_slice(&attestation[offset + 25..offset + 33]);

    // extract timestamp for expiry checks, convert from milliseconds to seconds
    let timestamp =
        u64::from_be_bytes(attestation[offset + 25..offset + 33].try_into().unwrap()) / 1000;

    // assert pcrs key
    assert_eq!(attestation[offset + 33], 0x64); // text of size 4
    assert_eq!(&attestation[offset + 34..offset + 38], b"pcrs");
    assert!(attestation[offset + 38] == 0xb0 || attestation[offset + 38] == 0xb1); // pcrs is a map of size 16 or 17

    // is there a custom PCR
    let is_custom = attestation[offset + 38] == 0xb1;

    // hasher for accumulating an image id
    let mut image_id_hasher = Sha256::new();
    // bitflags denoting what pcrs are part of the computation
    // this one has 0, 1, 2 and 16
    image_id_hasher.update(&((1u32 << 0) | (1 << 1) | (1 << 2) | (1 << 16)).to_be_bytes());

    offset += 39;
    assert_eq!(
        attestation[offset..offset + 3],
        [
            0x00, // pcr number
            0x58, // bytes with one byte length follows
            0x30, // 48 length
        ]
    );
    println!("PCR0: {:?}", &attestation[offset + 3..offset + 51]);
    image_id_hasher.update(&attestation[offset + 3..offset + 51]);

    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x01, 0x58, 0x30]);
    println!("PCR1: {:?}", &attestation[offset + 3..offset + 51]);
    image_id_hasher.update(&attestation[offset + 3..offset + 51]);

    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x02, 0x58, 0x30]);
    println!("PCR2: {:?}", &attestation[offset + 3..offset + 51]);
    image_id_hasher.update(&attestation[offset + 3..offset + 51]);

    // skip rest of the pcrs, 3 to 15
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x03, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x04, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x05, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x06, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x07, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x08, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x09, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0a, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0b, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0c, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0d, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0e, 0x58, 0x30]);
    offset += 51;
    assert_eq!(attestation[offset..offset + 3], [0x0f, 0x58, 0x30]);
    offset += 51;

    // process custom pcr if exists
    if is_custom {
        assert_eq!(attestation[offset..offset + 3], [0x10, 0x58, 0x30]);
        println!("PCR16: {:?}", &attestation[offset + 3..offset + 51]);
        image_id_hasher.update(&attestation[offset + 3..offset + 51]);
        offset += 51;
    } else {
        image_id_hasher.update(&[0u8; 48]);
    }
    println!("Skipped rest of the pcrs");

    // commit image id
    commit_slice(&image_id_hasher.finalize());

    // assert certificate key
    assert_eq!(attestation[offset], 0x6b); // text of size 11
    assert_eq!(&attestation[offset + 1..offset + 12], b"certificate");
    // get leaf certificate
    assert_eq!(attestation[offset + 12], 0x59); // bytes where two byte length follows
    let leaf_cert_size =
        u16::from_be_bytes([attestation[offset + 13], attestation[offset + 14]]) as usize;
    let leaf_cert_offset = offset + 15;
    let leaf_cert =
        x509_cert::Certificate::from_der(&attestation[offset + 15..offset + 15 + leaf_cert_size])
            .unwrap();
    offset += 15 + leaf_cert_size;

    // assert cabundle key
    assert_eq!(attestation[offset], 0x68); // text of length 8
    assert_eq!(&attestation[offset + 1..offset + 9], b"cabundle");

    // cabundle should be an array, read length
    let chain_size = attestation[offset + 9];
    // just restrict chain size instead of figuring out parsing too much
    // works for tiny field encoded cabundle up to 16 length
    assert!(chain_size > 0x80 && chain_size <= 0x90);
    let chain_size = chain_size - 0x80; // real size is minus 0x80 for bytes type

    // verify certificate chain
    // first certificate in the list is the root certificate
    // last certificate in the list signs the leaf certificate obtained above

    // track start of each section so we know where to proceed from after the block
    offset = offset + 10;
    {
        // start with the root cert

        // parse root cert
        assert_eq!(attestation[offset], 0x59); // bytes where two byte length follows
        let size = u16::from_be_bytes([attestation[offset + 1], attestation[offset + 2]]) as usize;

        // cert with the pubkey, start with the root
        let mut parent_cert =
            x509_cert::Certificate::from_der(&attestation[offset + 3..offset + 3 + size]).unwrap();
        // assert parent cert expiry
        assert!(
            parent_cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                < timestamp
        );
        assert!(
            parent_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                > timestamp
        );

        // commit the root pubkey
        let pubkey = parent_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        println!(
            "Root certificate public key: {} bytes: {:?}",
            pubkey.len(),
            pubkey
        );
        // assert that the pubkey size is 97 in case it changes later
        assert_eq!(pubkey.len(), 97);
        assert_eq!(pubkey[0], 0x04);
        commit_slice(&pubkey[1..]);

        // start of next cert that is to be verified
        offset = offset + 3 + size;

        for _ in 0..chain_size - 1 {
            // parse child cert
            assert_eq!(attestation[offset], 0x59); // bytes where two byte length follows
            let size =
                u16::from_be_bytes([attestation[offset + 1], attestation[offset + 2]]) as usize;

            // parse the next cert and get the public key
            let child_cert =
                x509_cert::Certificate::from_der(&attestation[offset + 3..offset + 3 + size])
                    .unwrap();
            // assert cert expiry
            assert!(
                child_cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs()
                    < timestamp
            );
            assert!(
                child_cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs()
                    > timestamp
            );

            // verify signature
            // the tbs cert is already available in DER form in the attestation, use that
            assert_eq!(attestation[offset + 3], 0x30); // ASN.1 Sequence
            assert_eq!(attestation[offset + 4], 0x82); // two byte length follows
            assert_eq!(attestation[offset + 7], 0x30); // ASN.1 Sequence
            assert_eq!(attestation[offset + 8], 0x82); // two byte length follows
            let cert_size =
                u16::from_be_bytes([attestation[offset + 9], attestation[offset + 10]]) as usize;
            let msg = &attestation[offset + 7..offset + 11 + cert_size];
            let sig = Signature::from_der(&child_cert.signature.raw_bytes()).unwrap();
            let pubkey = parent_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let vkey = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
            vkey.verify(&msg, &sig).unwrap();

            // set up for next iteration
            parent_cert = child_cert;
            offset = offset + 3 + size;
        }

        // assert leaf cert expiry
        assert!(
            leaf_cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
                < timestamp
        );
        assert!(
            leaf_cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
                > timestamp
        );

        // verify the leaf cert with the last cert in the chain
        // the tbs cert is already available in DER form in the attestation, use that
        assert_eq!(attestation[leaf_cert_offset], 0x30); // ASN.1 Sequence
        assert_eq!(attestation[leaf_cert_offset + 1], 0x82); // two byte length follows
        assert_eq!(attestation[leaf_cert_offset + 4], 0x30); // ASN.1 Sequence
        assert_eq!(attestation[leaf_cert_offset + 5], 0x82); // two byte length follows
        let cert_size = u16::from_be_bytes([
            attestation[leaf_cert_offset + 6],
            attestation[leaf_cert_offset + 7],
        ]) as usize;
        let msg = &attestation[leaf_cert_offset + 4..leaf_cert_offset + 8 + cert_size];
        let sig = Signature::from_der(&leaf_cert.signature.raw_bytes()).unwrap();
        let pubkey = parent_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let vkey = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        vkey.verify(&msg, &sig).unwrap();
    }

    // assert public_key key
    assert_eq!(attestation[offset], 0x6a); // text of size 10
    assert_eq!(&attestation[offset + 1..offset + 11], b"public_key");

    offset = offset + 11;

    // commit public key
    let pubkey_len = if attestation[offset] >= 0x40 && attestation[offset] <= 0x57 {
        // length is part of type byte
        let len = attestation[offset] - 0x40;

        // set offset to start of pubkey
        offset += 1;

        // return len
        len as usize
    } else {
        // only allow one byte length
        assert_eq!(attestation[offset], 0x58);
        let len = attestation[offset + 1] as usize;

        // set offset to start of pubkey
        offset += 2;

        // return len
        len
    };

    println!(
        "Public key: {pubkey_len} bytes: {:?}",
        &attestation[offset..offset + pubkey_len]
    );
    commit_slice(&[pubkey_len as u8]);
    commit_slice(&attestation[offset..offset + pubkey_len]);

    offset = offset + pubkey_len;

    // assert user_data key
    assert_eq!(attestation[offset], 0x69); // text of size 9
    assert_eq!(&attestation[offset + 1..offset + 10], b"user_data");
    // commit user data
    // handle cases up to 65536 size
    let (user_data_size, user_data) = if attestation[offset + 10] == 0xf6 {
        // empty
        (0, [].as_slice())
    } else if attestation[offset + 10] >= 0x40 && attestation[offset + 10] <= 0x57 {
        // length is part of type byte
        let size = (attestation[offset + 10] - 0x40) as u16;

        (size, &attestation[offset + 11..offset + 11 + size as usize])
    } else if attestation[offset + 10] == 0x58 {
        // one byte length follows
        let size = attestation[offset + 11] as u16;

        (size, &attestation[offset + 12..offset + 12 + size as usize])
    } else {
        // only allow 2 byte lengths as max
        // technically, this is already enforced by COSE doc size parsing
        assert_eq!(attestation[offset + 10], 0x59);

        let size = u16::from_be_bytes([attestation[offset + 11], attestation[offset + 12]]);

        (size, &attestation[offset + 13..offset + 13 + size as usize])
    };
    println!("User data: {} bytes: {:?}", user_data_size, user_data);
    // commit 2 byte length, then data
    commit_slice(&user_data_size.to_be_bytes());
    commit_slice(user_data);

    // prepare COSE verification hash
    let mut hasher = sha2::Sha384::new();
    // array with 4 elements
    hasher.update(&[0x84]);
    // context field length
    hasher.update(&[0x6a]);
    // context field
    hasher.update("Signature1");
    // body_protected
    hasher.update(&[0x44, 0xa1, 0x01, 0x38, 0x22]);
    // empty aad
    hasher.update(&[0x40]);
    // payload length
    hasher.update(&[0x59, attestation[8], attestation[9]]);
    // payload
    hasher.update(&attestation[10..10 + payload_size]);
    let hash = hasher.finalize();

    // verify signature
    // signature size
    assert_eq!(attestation[payload_size + 10], 0x58); // bytes where one byte length follows
    assert_eq!(attestation[payload_size + 11], 0x60); // 96 length

    let leaf_cert_pubkey = leaf_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_owned();
    let verifying_key = VerifyingKey::from_sec1_bytes(&leaf_cert_pubkey).unwrap();
    let r: [u8; 48] = attestation[12 + payload_size..60 + payload_size]
        .try_into()
        .unwrap();
    let s: [u8; 48] = attestation[60 + payload_size..108 + payload_size]
        .try_into()
        .unwrap();
    let signature = Signature::from_scalars(r, s).unwrap();

    verifying_key.verify_prehash(&hash, &signature).unwrap();
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::verify;

    // TODO: add more extensive tests

    // NOTE: Seems a bit convoluted, idk if it can be simplified
    fn create_committer() -> (Rc<RefCell<Vec<u8>>>, impl Fn(&[u8])) {
        let env = Rc::new(RefCell::new(vec![]));

        let env_clone = env.clone();

        let commit_slice = move |slice: &[u8]| {
            env_clone.borrow_mut().extend_from_slice(slice);
        };

        (env, commit_slice)
    }

    #[test]
    fn test_aws() {
        // generated using `curl <ip>:<port>/attestation/raw` on the attestation server of a
        // real Nitro enclave
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws.bin")
                .unwrap();

        let (journal, committer) = create_committer();

        verify(&attestation, committer);

        let expected_journal = [
            // timestamp
            "00000193bef3f3b0",
            // image id
            "a6b0824d3c47f51542b3a18e6245c408490bef88ddc8d5e1bf8b95ec7eba1602",
            // root pubkey
            "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b17607",
            "0ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
            // pubkey len
            "40",
            // pubkey
            "e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd3",
            "6d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb",
            // user data len
            "0000",
        ].join("");

        assert_eq!(
            expected_journal,
            hex::encode(journal.borrow_mut().as_slice())
        );
    }

    #[test]
    fn test_custom() {
        // generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
        // on a custom mock attestation server running locally
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/custom.bin")
                .unwrap();

        let (journal, committer) = create_committer();

        verify(&attestation, committer);

        let expected_journal = [
            // timestamp
            "00000193bf444e30",
            // image id
            "b45dfd1807c1f4b81ef28b44682fba5d4d5522baac808a44b7302cbfda5144e7",
            // root pubkey
            "6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188",
            "fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410",
            // pubkey len
            "04",
            // pubkey
            "12345678",
            // user data len
            "0003",
            // user data
            "abcdef",
        ].join("");

        assert_eq!(
            expected_journal,
            hex::encode(journal.borrow_mut().as_slice())
        );
    }

    #[test]
    fn test_aws_pcr16() {
        // generated using `curl <ip>:<port>/attestation/raw` on the attestation server of a
        // real Nitro enclave
        let attestation = std::fs::read(
            file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws_pcr16.bin",
        )
        .unwrap();

        let (journal, committer) = create_committer();

        verify(&attestation, committer);

        let expected_journal = [
            // timestamp
            "00000196811b1c0b",
            // image id
            "c28909dc8803cf0edf6113f3fb81d0494f4c92b63087242200e18a5be347aacd",
            // root pubkey
            "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b17607",
            "0ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
            // pubkey len
            "20",
            // pubkey
            "2af77183f4772f00e269c7ffadb0eca298bf76711bbe94471a4944ede5ada084",
            // user data len
            "0000",
        ].join("");

        assert_eq!(
            expected_journal,
            hex::encode(journal.borrow_mut().as_slice())
        );
    }

    #[test]
    fn test_custom_pcr16() {
        // generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
        // on a custom mock attestation server running locally
        let attestation = std::fs::read(
            file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/custom_pcr16.bin",
        )
        .unwrap();

        let (journal, committer) = create_committer();

        verify(&attestation, committer);

        let expected_journal = [
            // timestamp
            "00000196870610d9",
            // image id
            "20a182763745f956ddee6f8e9d14a66e23db836c0eb1a769a2ef4d3ab77bef1b",
            // root pubkey
            "6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188",
            "fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410",
            // pubkey len
            "04",
            // pubkey
            "12345678",
            // user data len
            "0003",
            // user data
            "abcdef",
        ].join("");

        assert_eq!(
            expected_journal,
            hex::encode(journal.borrow_mut().as_slice())
        );
    }
}
