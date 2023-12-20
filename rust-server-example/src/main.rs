//! A TLS server that accepts connections using a custom `Acceptor`, demonstrating how fresh
//! CRL information can be retrieved per-client connection to use for revocation checking of
//! client certificates.
//!
//! For a more complete server demonstration, see `tlsserver-mio.rs`.

use std::fs::File;
use std::io::Write;

use std::sync::Arc;

use docopt::Docopt;
use rustls::server::danger::ClientCertVerifier;
use serde_derive::Deserialize;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{Acceptor, ClientHello, ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;

fn main() {
    env_logger::init();
    let version = concat!(
        env!("CARGO_PKG_NAME"),
        ", version: ",
        env!("CARGO_PKG_VERSION")
    )
    .to_string();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new().parse_filters("trace").init();
    }

    let write_pem = |path: &str, pem: &str| {
        let mut file = File::create(path).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
    };

    // Create a test PKI with:
    // * An issuing CA certificate.
    // * A server certificate issued by the CA.
    // * A client certificate issued by the CA.
    let test_pki = Arc::new(TestPki::new());

    // Write out the parts of the test PKI a client will need to connect:
    // * The CA certificate for validating the server certificate.
    // * The client certificate and key for its presented mTLS identity.
    write_pem(
        &args.flag_ca_path.unwrap_or("ca-cert.pem".to_string()),
        &test_pki.ca_cert.serialize_pem().unwrap(),
    );
    write_pem(
        &args
            .flag_client_cert_path
            .unwrap_or("client-cert.pem".to_string()),
        &test_pki
            .client_cert
            .serialize_pem_with_signer(&test_pki.ca_cert)
            .unwrap(),
    );
    write_pem(
        &args
            .flag_client_key_path
            .unwrap_or("client-key.pem".to_string()),
        &test_pki.client_cert.serialize_private_key_pem(),
    );

    // Start a TLS server accepting connections as they arrive.
    let listener =
        std::net::TcpListener::bind(format!("[::]:{}", args.flag_port.unwrap_or(4443))).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we've consumed a full client hello and are ready to accept a
        // connection.
        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = test_pki.server_config(accepted.client_hello());
        let mut conn = accepted.into_connection(config).unwrap();

        // Proceed with handling the ServerConnection
        // Important: We do no error handling here, but you should!
        _ = conn.complete_io(&mut stream);
    }
}

#[derive(Debug)]
struct CustomizedClientVerifier(Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for CustomizedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// A test PKI with a CA certificate, server certificate, and client certificate.
struct TestPki {
    roots: Arc<RootCertStore>,
    ca_cert: rcgen::Certificate,
    client_cert: rcgen::Certificate,
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    /// Create a new test PKI using `rcgen`.
    fn new() -> Self {
        // Create an issuer CA cert.
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der =
            CertificateDer::from(server_cert.serialize_der_with_signer(&ca_cert).unwrap());
        let server_key_der = PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der());

        // Create a client end entity cert issued by the CA.
        let mut client_ee_params = rcgen::CertificateParams::new(Vec::new());
        client_ee_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example Client");
        client_ee_params.is_ca = rcgen::IsCa::NoCa;
        client_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        client_ee_params.alg = alg;
        client_ee_params.serial_number = Some(rcgen::SerialNumber::from(vec![0xC0, 0xFF, 0xEE]));
        let client_cert = rcgen::Certificate::from_params(client_ee_params).unwrap();

        // Create a root cert store that includes the CA certificate.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.serialize_der().unwrap()))
            .unwrap();
        Self {
            roots: roots.into(),
            ca_cert,
            client_cert,
            server_cert_der,
            server_key_der: server_key_der.into(),
        }
    }

    /// Generate a server configuration for the client using the test PKI.
    ///
    /// Importantly this creates a new client certificate verifier per-connection so that the server
    /// can read in the latest CRL content from disk.
    ///
    /// Since the presented client certificate is not available in the `ClientHello` the server
    /// must know ahead of time which CRLs it cares about.
    fn server_config(&self, _hello: ClientHello) -> Arc<ServerConfig> {
        // Construct a fresh verifier using the test PKI roots, and the updated CRL.
        let web_pki_verifier = WebPkiClientVerifier::builder(self.roots.clone())
            .build()
            .unwrap();
        let verifier = Arc::new(CustomizedClientVerifier(web_pki_verifier));

        // Build a server config using the fresh verifier. If necessary, this could be customized
        // based on the ClientHello (e.g. selecting a different certificate, or customizing
        // supported algorithms/protocol versions).
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server_cert_der.clone()],
                PrivatePkcs8KeyDer::from(self.server_key_der.secret_der().to_owned()).into(),
            )
            .unwrap();

        // Allow using SSLKEYLOGFILE.
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}

const USAGE: &str = "
Runs a TLS server on :PORT.  The default PORT is 4443.

Usage:
  server_example [options]
  server_example  (--version | -v)
  server_example  (--help | -h)

Options:
    -p, --port PORT                 Listen on PORT [default: 4443].
    --verbose                       Emit log output.
    --ca-path PATH                  Write the CA cert PEM to PATH [default: ca-cert.pem].
    --client-cert-path PATH         Write the client cert PEM to PATH [default: client-cert.pem].
    --client-key-path PATH          Write the client key PEM to PATH [default: client-key.pem].
    --version, -v                   Show tool version.
    --help, -h                      Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_ca_path: Option<String>,
    flag_client_cert_path: Option<String>,
    flag_client_key_path: Option<String>,
}
