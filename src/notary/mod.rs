use futures::{AsyncRead, AsyncWrite};
use p256::pkcs8::DecodePrivateKey;
use tlsn_verifier::tls::{Verifier, VerifierConfig};

/// Default for the maximum number of bytes that can be sent (32Kb).
pub const DEFAULT_MAX_SENT_LIMIT: usize = 1 << 16;
/// Default for the maximum number of bytes that can be received (32Kb).
pub const DEFAULT_MAX_RECV_LIMIT: usize = 1 << 16;

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    // Load the notary signing key
    let signing_key_str = std::str::from_utf8(include_bytes!("../fixture/notary.key")).unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, p256::ecdsa::Signature>(conn, &signing_key)
        .await
        .unwrap();
}
