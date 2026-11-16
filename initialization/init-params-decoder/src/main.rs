use std::{
    convert::identity,
    fs::{create_dir_all, read_to_string, write},
    path::{Component, Path, PathBuf},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use libsodium_sys::{
    crypto_box_SEALBYTES, crypto_box_seal_open, crypto_scalarmult_base, sodium_init,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Args {
    /// Init params file
    #[arg(long, default_value = "/app/init-params")]
    init_params_path: String,

    /// Derive server endpoint
    #[arg(long, default_value = "http://127.0.0.1:1100")]
    derive_endpoint: String,

    /// Directory to write the decoded params into,
    /// the digest always uses /init-params
    #[arg(long, default_value = "/init-params")]
    output_dir: String,

    /// How long to keep retrying the derive server for the decryption key,
    /// only used if there are encrypted params
    #[arg(long, default_value_t = 600)]
    key_fetch_timeout_secs: u64,
}

// paths in the digest are always relative to this
const DIGEST_ROOT: &str = "/init-params/";

// derive server takes a while to come up since it needs the kms
const KEY_FETCH_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const KEY_FETCH_MAX_BACKOFF: Duration = Duration::from_secs(15);
const KEY_FETCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run().inspect_err(|e| error!("{e:?}"))
}

fn run() -> Result<()> {
    // parse args
    let args = Args::parse();

    // SAFETY: no params, return value is checked properly
    if unsafe { sodium_init() } < 0 {
        bail!("failed to init libsodium");
    }

    // parse init params
    let init_params_str = read_to_string(args.init_params_path)
        .context("failed to read init params, should never happen")?;

    let derive_endpoint = args.derive_endpoint;
    let timeout = Duration::from_secs(args.key_fetch_timeout_secs);
    decode(&init_params_str, Path::new(&args.output_dir), || {
        retry_with_backoff(
            timeout,
            KEY_FETCH_INITIAL_BACKOFF,
            KEY_FETCH_MAX_BACKOFF,
            || fetch_encryption_key(&derive_endpoint),
        )
    })
}

fn decode(
    init_params_str: &str,
    output_dir: &Path,
    fetch_key: impl FnOnce() -> Result<[u8; 32]>,
) -> Result<()> {
    if init_params_str.is_empty() {
        // ignore empty params
        info!("empty init params");
        return Ok(());
    }
    let init_params = serde_json::from_str::<InitParamsList>(init_params_str)
        .context("failed to parse init params")?;

    // fetch key, only if there is something to decrypt
    // enclaves that do not use encrypted params should not need the kms to boot
    // done before anything is written so a failure here leaves nothing behind
    let keys = if init_params.params.iter().any(|x| x.should_decrypt) {
        let sk = fetch_key().context("failed to fetch encryption key")?;
        let mut pk = [0u8; 32];

        // SAFETY: pk and sk are the right size
        // cannot fail, ignore return value
        unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()) };

        Some((pk, sk))
    } else {
        info!("no encrypted params, skipping key fetch");
        None
    };

    let digest = init_params
        .params
        .into_iter()
        .map(|init_param| -> Result<Option<[u8; 32]>> {
            info!(init_param.path, "processing");

            // everything should be normal components, no root or current or parent dirs
            if PathBuf::from(&init_param.path)
                .components()
                .any(|x| !matches!(x, Component::Normal(_)))
            {
                bail!("invalid path")
            }

            let path = output_dir.join(&init_param.path);
            // the digest does not depend on where the files get written
            let digest_path = PathBuf::from(DIGEST_ROOT.to_owned() + &init_param.path);

            // we want to fail closed, hence detect errors as well
            if path
                .try_exists()
                .context("failed to check if path exists")?
            {
                bail!("file already exists");
            }

            let mut contents = BASE64_STANDARD
                .decode(init_param.contents.as_bytes())
                .context("failed to decode contents")?;

            if init_param.should_decrypt {
                // only ever decrypt with the key from the derive server
                let (pk, sk) = keys.as_ref().context("missing encryption key")?;

                if contents.len() > 65535 {
                    bail!("invalid content length");
                }

                // SAFETY: contents is big enough for the decrypted message
                // in-place decryption is supported by libsodium
                // pk and sk are the right size
                let res = unsafe {
                    crypto_box_seal_open(
                        contents.as_mut_ptr(),
                        contents.as_ptr(),
                        contents.len() as u64,
                        pk.as_ptr(),
                        sk.as_ptr(),
                    )
                };
                if res != 0 {
                    bail!("failed to decrypt");
                }

                // successfully decrypted, truncate seal
                contents.truncate(contents.len() - crypto_box_SEALBYTES as usize);
            }

            create_dir_all(path.parent().ok_or(anyhow!("failed to get parent"))?)
                .context("failed to create dirs")?;
            write(&path, &contents).context("failed to write contents")?;

            if init_param.should_attest {
                let mut hasher = Sha256::new();
                hasher.update(digest_path.as_os_str().len().to_le_bytes());
                hasher.update(digest_path.as_os_str().as_encoded_bytes());
                hasher.update(contents.len().to_le_bytes());
                hasher.update(contents.as_slice());

                Ok(Some(hasher.finalize().into()))
            } else {
                Ok(None)
            }
        })
        // will short circuit if anything errors
        .collect::<Result<Vec<_>>>()
        .context("failed to process init params")?
        .into_iter()
        // filter out Nones
        .filter_map(identity)
        // accumulate futher into a single hash
        .fold(Sha256::new(), |mut hasher, param_hash| {
            hasher.update(param_hash);
            hasher
        })
        .finalize();

    if digest.as_slice()
        != BASE64_STANDARD
            .decode(init_params.digest)
            .context("failed to decode digest")?
            .as_slice()
    {
        bail!("digest mismatch");
    }

    Ok(())
}

// retries op with exponential backoff till it succeeds or the timeout runs out
// always tries at least once
fn retry_with_backoff<T>(
    timeout: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
    mut op: impl FnMut() -> Result<T>,
) -> Result<T> {
    let deadline = Instant::now() + timeout;
    let mut backoff = initial_backoff;
    loop {
        let err = match op() {
            Ok(res) => return Ok(res),
            Err(err) => err,
        };

        let now = Instant::now();
        if now >= deadline {
            return Err(err.context("timed out"));
        }

        warn!("{err:?}");
        warn!("retrying in {backoff:?}");
        sleep(backoff.min(deadline - now));
        backoff = (backoff * 2).min(max_backoff);
    }
}

fn fetch_encryption_key(endpoint: &str) -> Result<[u8; 32]> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(KEY_FETCH_REQUEST_TIMEOUT))
        // the derive server is local, never go through a proxy from the env
        .proxy(None)
        .build()
        .into();

    agent
        .get(endpoint.to_owned() + "/derive/x25519")
        .query("path", "oyster.init-params")
        .call()
        .context("failed to call derive server")?
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?
        .as_slice()
        .try_into()
        .context("failed to parse reponse")
}

#[derive(Deserialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    #[serde(default = "_default_true")]
    should_attest: bool,
    #[serde(default)]
    should_decrypt: bool,
}

#[derive(Deserialize)]
struct InitParamsList {
    digest: String, // base64 encoded
    params: Vec<InitParam>,
}

// blergh
const fn _default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs::{read, remove_dir_all},
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    use libsodium_sys::{crypto_box_keypair, crypto_box_seal};

    use super::*;

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "init-params-decoder-test-{}-{}",
                std::process::id(),
                DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = remove_dir_all(&self.0);
        }
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        assert!(unsafe { sodium_init() } >= 0);
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        unsafe { crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        (pk, sk)
    }

    fn seal(contents: &[u8], pk: &[u8; 32]) -> Vec<u8> {
        let mut sealed = vec![0u8; contents.len() + crypto_box_SEALBYTES as usize];
        unsafe {
            crypto_box_seal(
                sealed.as_mut_ptr(),
                contents.as_ptr(),
                contents.len() as u64,
                pk.as_ptr(),
            )
        };
        sealed
    }

    // same computation as oyster-cvm, over plaintext contents of attested params
    fn digest(attested: &[(&str, &[u8])]) -> String {
        let mut outer = Sha256::new();
        for (path, contents) in attested {
            let path = DIGEST_ROOT.to_owned() + path;
            let mut hasher = Sha256::new();
            hasher.update(path.len().to_le_bytes());
            hasher.update(path.as_bytes());
            hasher.update(contents.len().to_le_bytes());
            hasher.update(contents);
            outer.update(hasher.finalize());
        }
        BASE64_STANDARD.encode(outer.finalize())
    }

    fn param(path: &str, contents: &[u8], should_attest: bool, should_decrypt: bool) -> String {
        serde_json::json!({
            "path": path,
            "contents": BASE64_STANDARD.encode(contents),
            "should_attest": should_attest,
            "should_decrypt": should_decrypt,
        })
        .to_string()
    }

    fn init_params(digest: &str, params: &[String]) -> String {
        format!(
            r#"{{"digest":"{}","params":[{}]}}"#,
            digest,
            params.join(",")
        )
    }

    fn no_key() -> Result<[u8; 32]> {
        panic!("key should not be fetched");
    }

    #[test]
    fn empty_init_params_do_nothing() {
        let dir = TestDir::new();

        decode("", &dir.0, no_key).unwrap();

        assert!(!dir.0.exists());
    }

    #[test]
    fn plain_params_do_not_fetch_the_key() {
        let dir = TestDir::new();
        let params = init_params(
            &digest(&[("docker-compose.yml", b"services: {}"), ("a/b", b"hello")]),
            &[
                param("docker-compose.yml", b"services: {}", true, false),
                param("a/b", b"hello", true, false),
            ],
        );

        decode(&params, &dir.0, no_key).unwrap();

        assert_eq!(
            read(dir.0.join("docker-compose.yml")).unwrap(),
            b"services: {}"
        );
        assert_eq!(read(dir.0.join("a/b")).unwrap(), b"hello");
    }

    #[test]
    fn encrypted_params_are_decrypted_with_the_fetched_key() {
        let dir = TestDir::new();
        let (pk, sk) = keypair();
        let params = init_params(
            &digest(&[
                ("docker-compose.yml", b"services: {}"),
                ("secret", b"hunter2"),
            ]),
            &[
                param("docker-compose.yml", b"services: {}", true, false),
                param("secret", &seal(b"hunter2", &pk), true, true),
            ],
        );

        decode(&params, &dir.0, || Ok(sk)).unwrap();

        assert_eq!(read(dir.0.join("secret")).unwrap(), b"hunter2");
    }

    #[test]
    fn encrypted_params_fail_with_the_wrong_key() {
        let dir = TestDir::new();
        let (pk, _) = keypair();
        let (_, other_sk) = keypair();
        let params = init_params(
            &digest(&[("secret", b"hunter2")]),
            &[param("secret", &seal(b"hunter2", &pk), true, true)],
        );

        let err = decode(&params, &dir.0, || Ok(other_sk)).unwrap_err();

        assert!(format!("{err:?}").contains("failed to decrypt"));
        assert!(!dir.0.join("secret").exists());
    }

    #[test]
    fn key_fetch_failure_fails_before_anything_is_written() {
        let dir = TestDir::new();
        let (pk, _) = keypair();
        let params = init_params(
            &digest(&[
                ("docker-compose.yml", b"services: {}"),
                ("secret", b"hunter2"),
            ]),
            &[
                param("docker-compose.yml", b"services: {}", true, false),
                param("secret", &seal(b"hunter2", &pk), true, true),
            ],
        );

        let err = decode(&params, &dir.0, || bail!("kms down")).unwrap_err();

        assert!(format!("{err:?}").contains("failed to fetch encryption key"));
        assert!(!dir.0.exists());
    }

    #[test]
    fn digest_mismatch_fails() {
        let dir = TestDir::new();
        let params = init_params(
            &digest(&[("a", b"hello")]),
            &[param("a", b"goodbye", true, false)],
        );

        let err = decode(&params, &dir.0, no_key).unwrap_err();

        assert!(format!("{err:?}").contains("digest mismatch"));
    }

    #[test]
    fn empty_digest_fails() {
        let dir = TestDir::new();
        let params = init_params("", &[param("a", b"hello", true, false)]);

        let err = decode(&params, &dir.0, no_key).unwrap_err();

        assert!(format!("{err:?}").contains("digest mismatch"));
    }

    #[test]
    fn invalid_paths_fail() {
        for path in ["../a", "/a", "a/../b", "./a"] {
            let dir = TestDir::new();
            let params = init_params(&digest(&[]), &[param(path, b"hello", false, false)]);

            let err = decode(&params, &dir.0, no_key).unwrap_err();

            assert!(format!("{err:?}").contains("invalid path"), "{path}");
        }
    }

    #[test]
    fn duplicate_paths_fail() {
        let dir = TestDir::new();
        let params = init_params(
            &digest(&[("a", b"hello"), ("a", b"hello")]),
            &[
                param("a", b"hello", true, false),
                param("a", b"hello", true, false),
            ],
        );

        let err = decode(&params, &dir.0, no_key).unwrap_err();

        assert!(format!("{err:?}").contains("file already exists"));
    }

    #[test]
    fn retry_returns_once_op_succeeds() {
        let calls = Cell::new(0);

        let res = retry_with_backoff(
            Duration::from_secs(5),
            Duration::from_millis(1),
            Duration::from_millis(4),
            || {
                calls.set(calls.get() + 1);
                if calls.get() < 4 {
                    bail!("not yet");
                }
                Ok(calls.get())
            },
        )
        .unwrap();

        assert_eq!(res, 4);
    }

    #[test]
    fn retry_gives_up_after_the_timeout() {
        let calls = Cell::new(0);
        let start = Instant::now();

        let err = retry_with_backoff(
            Duration::from_millis(100),
            Duration::from_millis(10),
            Duration::from_millis(20),
            || -> Result<()> {
                calls.set(calls.get() + 1);
                bail!("still down")
            },
        )
        .unwrap_err();

        assert!(format!("{err:?}").contains("timed out"));
        assert!(format!("{err:?}").contains("still down"));
        assert!(calls.get() > 2);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn retry_tries_once_with_zero_timeout() {
        let calls = Cell::new(0);

        let res = retry_with_backoff(
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(1),
            || -> Result<()> {
                calls.set(calls.get() + 1);
                bail!("down")
            },
        );

        assert!(res.is_err());
        assert_eq!(calls.get(), 1);
    }

    // derive server that refuses the first few requests, like one that is
    // still waiting on the kms
    fn flaky_derive_server(failures: usize, key: [u8; 32]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());

        thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                assert!(
                    // ureq percent encodes the dot and the dash
                    request.starts_with("GET /derive/x25519?path=oyster%2Einit%2Dparams "),
                    "{request:?}"
                );

                if i < failures {
                    stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 32\r\nconnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.write_all(&key).unwrap();
                }
            }
        });

        endpoint
    }

    #[test]
    fn key_fetch_retries_till_the_derive_server_is_ready() {
        let dir = TestDir::new();
        let (pk, sk) = keypair();
        let endpoint = flaky_derive_server(3, sk);
        let params = init_params(
            &digest(&[("secret", b"hunter2")]),
            &[param("secret", &seal(b"hunter2", &pk), true, true)],
        );

        decode(&params, &dir.0, || {
            retry_with_backoff(
                Duration::from_secs(10),
                Duration::from_millis(10),
                Duration::from_millis(50),
                || fetch_encryption_key(&endpoint),
            )
        })
        .unwrap();

        assert_eq!(read(dir.0.join("secret")).unwrap(), b"hunter2");
    }

    #[test]
    fn key_fetch_fails_when_nothing_is_listening() {
        // bind and drop to get a port that refuses connections
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let err = retry_with_backoff(
            Duration::from_millis(200),
            Duration::from_millis(10),
            Duration::from_millis(50),
            || fetch_encryption_key(&endpoint),
        )
        .unwrap_err();

        assert!(format!("{err:?}").contains("failed to call derive server"));
    }
}
