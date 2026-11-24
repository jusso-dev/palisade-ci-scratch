//! Authenticode for PE images.
//!
//! - [`hash`]: the Authenticode image hash (#47), which identifies a PE file
//!   independently of its embedded signature.
//! - [`page`]: page hash tables (#47), built from a file and checked against
//!   the table a signature carries.
//! - [`hash_image_file`] and [`hash_image_reader`]: the flat hashes, the
//!   Authenticode digests and the page hash tables of a file, in one
//!   sequential read.
//! - Signature parsing and verification (#48): [`verify_pe`],
//!   [`verify_signatures`] and [`verify_certificate_table`] read every
//!   `WIN_CERTIFICATE` entry, decode each PKCS#7 SignedData and its nested
//!   signatures, and check them. The result is a [`SignatureReport`] with
//!   one [`SignatureInfo`] per signature, the primary signature and the
//!   file's [`SigningState`].
//!
//! # What "valid" means here
//!
//! A signature is [`SignatureStatus::Valid`] when all of these hold:
//!
//! 1. it parses as an Authenticode SignedData: content type
//!    `SPC_INDIRECT_DATA`, a `SPC_PE_IMAGE_DATA` indirect data, exactly one
//!    SignerInfo with `contentType` and `messageDigest` attributes;
//! 2. the `messageDigest` attribute equals the hash of the encoded
//!    `SpcIndirectDataContent`;
//! 3. a certificate in the blob matches the SignerInfo's signer identifier,
//!    and the signature over the DER-encoded authenticated attributes
//!    verifies with its public key;
//! 4. the image digest in the indirect data equals the file's Authenticode
//!    digest under the same algorithm;
//! 5. neither digest is MD2 or MD5;
//! 6. the image layout conforms to the Authenticode specification (#47).
//!    On a non-conformant image (data after or a misaligned certificate
//!    table, gaps or overlaps between sections, and so on) a matching
//!    digest is reported as [`SignatureStatus::NonConformantImage`], never
//!    as valid.
//!
//! It does **not** mean the signer is trusted.
//!
//! # Chains, trust and signer identity (#49)
//!
//! - [`CertSummary::from_der`] parses an X.509 certificate into every
//!   attribute signer rules match on: subject and issuer as ordered RDNs
//!   with typed components and a canonical DN string, serial, validity,
//!   algorithms, key size, thumbprints, TBS hashes, key identifiers, basic
//!   constraints, key usage, EKUs (named from the [`eku`] catalogue),
//!   policies, CRL and AIA URLs, and whether it is self-signed.
//! - [`build_chain`] orders a signature's embedded certificates into the
//!   as-provided chain (leaf, intermediates, PCA, root) and builds the
//!   full chain against a [`TrustConfig`] of policy-shipped anchors and
//!   intermediates, verifying every link's signature.
//! - [`evaluate_trust`] does that for every valid signature in a
//!   [`SignatureReport`] and picks the primary signature **among trusted
//!   signers only**, so a nested signature from an untrusted signer can
//!   never become primary. It yields the [`SignerIdentity`] publisher rules
//!   use, or, for a file with no trusted signer, an unverified
//!   [`VendorHint`]. [`SignatureReport::primary`] is the #48 choice by
//!   cryptographic validity alone; trust decisions must use
//!   [`TrustReport::primary`].
//!
//! # Timestamps, expiry and revocation (#50)
//!
//! - [`verify_timestamps`] verifies a signature's RFC 3161 and legacy
//!   countersignature timestamps against a TSA [`TrustConfig`].
//! - [`evaluate_validity`] judges every signature as of when it was made:
//!   the trusted signing time, expiry ([`ExpiryPolicy`], Lifetime Signing),
//!   revocation data the caller supplies ([`RevocationSet`], [`Crl`]), and
//!   per-certificate relaxations. Every outcome is one
//!   [`VerificationError`] code, shared with the OS event decoder (#58).
//!   Allow decisions must use [`ValidityReport::primary`].
//!
//! The OS trust store cross-check is the `os-trust` item of #48; catalogs
//! are [`crate::catalog`] (#51).
//!
//! # Untrusted input
//!
//! The certificate table and everything in it is attacker-controlled. The
//! ASN.1 layer (one module, `asn1.rs`, kept small for audit) accepts DER only, rejects BER indefinite lengths
//! and oversized or non-minimal lengths with a typed [`Asn1Error`], and
//! borrows instead of allocating, so no declared length sizes an
//! allocation. Fixed limits bound the rest: [`MAX_CERTIFICATE_ENTRIES`],
//! [`MAX_CERTIFICATE_TABLE_SIZE`], [`MAX_NESTING_DEPTH`],
//! [`MAX_SIGNATURES`], [`MAX_CERTIFICATES`], [`MAX_TIMESTAMPS`] and
//! [`MAX_WARNINGS`]. Nothing panics.
//!
//! # Cryptography
//!
//! Signature verification goes through one thin module that wraps `ring`
//! (ADR 0008). RSA PKCS#1 v1.5 (SHA-1, SHA-256, SHA-384, SHA-512), RSA-PSS
//! (SHA-256, SHA-384, SHA-512, with MGF1 over the same digest and a salt as
//! long as it) and ECDSA P-256 and P-384 (SHA-256, SHA-384) are verified.
//! ECDSA P-521, Ed25519, Ed448 and other combinations are reported as
//! [`SignatureStatus::Unsupported`], never as valid.
//!
//! # OS-native signer rules
//!
//! OS code integrity accepts only RSA signers of up to 4096 bits, and no
//! MD2 or MD5. [`SignatureInfo::os_ci_compatible`] is `false`, with the
//! reasons in [`SignatureInfo::os_ci_issues`], for any other signer, so a
//! compiled rule never silently fails.

#![forbid(unsafe_code)]

pub(crate) mod asn1;
mod chain;
mod crypto;
pub mod eku;
pub mod hash;
mod image;
pub mod page;
pub(crate) mod pkcs7;
mod revocation;
mod signature;
mod timestamp;
mod trust;
mod validity;
pub(crate) mod verify;
mod x509;

pub use asn1::{Asn1Error, Asn1ErrorKind, ObjectId};
pub use chain::{
    AnchorRef, AnchorSource, CertOrigin, ChainCert, ChainIssue, ChainPath, ChainReport,
    MAX_CHAIN_ISSUES, MAX_CHAIN_LENGTH, MAX_CHAIN_PATHS, MAX_EMBEDDED_CERTIFICATES,
    MAX_FILE_SIGNATURE_CHECKS, MAX_SIGNATURE_CHECKS, MAX_TRUST_CHECKS, TrustAnchor, TrustConfig,
    WellKnownRoot, WellKnownRootError, build_chain,
};
pub use eku::Eku;
pub use hash::{
    AuthenticodeError, AuthenticodeHashes, AuthenticodeStatus, HashRanges, HashScenario,
    NonConformance, RangeHasher, authenticode_hashes, hash_pe,
};
pub use image::{
    HEADER_PREFIX_LEN, ImageHashOptions, ImageHashStatus, ImageHashes, hash_image_file,
    hash_image_reader,
};
pub use page::{
    PAGE_SIZE, PageHashCheck, PageHashError, PageHashMismatch, PageHashTables, PageHasher,
    PageLayout, PageMismatchKind, page_hash_table, page_hash_tables, verify_page_hashes,
    verify_signature_page_hashes,
};
pub use palisade_core::VerificationError;
pub use pkcs7::{MAX_CERTIFICATES, MAX_TIMESTAMPS, MAX_WARNINGS};
pub use revocation::{
    CertRevocation, CertificateMatch, Coverage, Crl, CrlEntry, CrlError, MAX_CRL_CHECKS,
    MAX_CRL_ENTRIES, MAX_CRL_SIZE, MAX_CRLS, RevocationFailure, RevocationMode, RevocationReason,
    RevocationSet, RevocationSource, RevokedCertificate,
};
pub use signature::{
    BadSignature, CertificateEntry, CertificateTableError, Curve, DigestAlgorithm, InvalidReason,
    KeyAlgorithm, OsCiIssue, PageHashes, ReportWarning, SignatureAlgorithm, SignatureCheck,
    SignatureError, SignatureInfo, SignatureKind, SignatureReport, SignatureStatus,
    SignatureWarning, SignedMetadata, SignerAttributes, SignerIdentifier, SigningState,
    StatementType, TimestampKind, TimestampToken, Unsupported, VerifyOptions,
};
pub use timestamp::{
    MAX_FILE_TIMESTAMPS, MAX_TIMESTAMP_WARNINGS, MAX_TOKEN_CERTIFICATES, TimestampError,
    TimestampInfo, TimestampStatus, TimestampWarning, parse_timestamp_time, verify_timestamps,
};
pub use trust::{
    FilePublisherOsRule, IdentityIssue, NameSource, OsRuleRoot, PublisherName, PublisherOsRule,
    SignerIdentity, SignerTrust, TrustReport, UntrustedReason, VendorHint, evaluate_trust,
};
pub use validity::{
    CertificateOptions, CertificatePin, ChainRevocation, ErrorIgnoreFlags, ExpiryPolicy,
    IgnoreFlag, RelaxedCheck, SignatureValidity, TimeValidity, ValidityContext, ValidityPolicy,
    ValidityReport, ValidityWarning, evaluate_validity, status_error,
};
pub use verify::{
    MAX_CERTIFICATE_ENTRIES, MAX_CERTIFICATE_TABLE_SIZE, MAX_NESTING_DEPTH, MAX_SIGNATURES,
    verify_certificate_table, verify_pe, verify_signatures,
};
pub use x509::{
    AttributeKind, BasicConstraints, CertSummary, CertificateError, DistinguishedName, KeyUsage,
    NameAttribute,
};
