//! The result types of Authenticode signature verification (#48).

#![forbid(unsafe_code)]

use std::fmt;

use serde::Serialize;

use super::asn1::{Asn1Error, ObjectId};
use super::hash::AuthenticodeStatus;
use crate::hash::HashAlgorithm;
use crate::pe::WarningKind;

/// A digest algorithm named by a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    /// MD2. Broken; never trusted, and not even computed.
    Md2,
    /// MD5. Broken; never trusted.
    Md5,
    /// SHA-1. Not collision resistant; accepted for compatibility, and
    /// always loses primary selection to SHA-2.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlgorithm {
    /// Whether the algorithm is broken (MD2, MD5), so a signature using it
    /// is reported as [`SignatureStatus::WeakAlgorithm`] and never trusted.
    #[must_use]
    pub const fn is_broken(self) -> bool {
        matches!(self, Self::Md2 | Self::Md5)
    }

    /// Whether the algorithm is SHA-256 or stronger.
    #[must_use]
    pub const fn is_sha2(self) -> bool {
        matches!(self, Self::Sha256 | Self::Sha384 | Self::Sha512)
    }

    /// The matching file-hash algorithm, if Palisade computes it (all but
    /// MD2).
    #[must_use]
    pub const fn hash_algorithm(self) -> Option<HashAlgorithm> {
        match self {
            Self::Md2 => None,
            Self::Md5 => Some(HashAlgorithm::Md5),
            Self::Sha1 => Some(HashAlgorithm::Sha1),
            Self::Sha256 => Some(HashAlgorithm::Sha256),
            Self::Sha384 => Some(HashAlgorithm::Sha384),
            Self::Sha512 => Some(HashAlgorithm::Sha512),
        }
    }

    /// The digest length in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Md2 | Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// A named elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Curve {
    /// NIST P-256 (`prime256v1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`). Parsed and reported, but **not verified**:
    /// the crypto provider (ADR 0008) has no P-521 support.
    P521,
}

/// The algorithm of a signer's public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// RSA.
    Rsa,
    /// An RSA key restricted to RSA-PSS (`id-RSASSA-PSS`, RFC 4055).
    /// Reported as unsupported: its restrictions are not enforced yet.
    RsaPss,
    /// An elliptic-curve key on a known curve.
    Ec(Curve),
    /// An elliptic-curve key on another curve.
    EcOther(ObjectId),
    /// Ed25519. Reported as unsupported.
    Ed25519,
    /// Ed448. Reported as unsupported.
    Ed448,
    /// Any other algorithm.
    Other(ObjectId),
}

/// The algorithm a SignerInfo's signature uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSA PKCS#1 v1.5 over this digest.
    RsaPkcs1(DigestAlgorithm),
    /// RSA-PSS.
    RsaPss {
        /// The message digest.
        digest: DigestAlgorithm,
        /// The MGF1 digest.
        mgf1_digest: DigestAlgorithm,
        /// The salt length in bytes.
        salt_len: u32,
    },
    /// ECDSA over this digest.
    Ecdsa(DigestAlgorithm),
    /// Ed25519. Reported as unsupported.
    Ed25519,
    /// Ed448. Reported as unsupported.
    Ed448,
    /// Any other algorithm, or RSA-PSS with parameters that name an unknown
    /// digest or mask function.
    Other(ObjectId),
}

/// Why a signature could not be verified. A signature in this state is
/// **never** treated as valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Unsupported {
    /// A broken digest algorithm (MD2, MD5).
    WeakAlgorithm(DigestAlgorithm),
    /// A digest algorithm the scheme cannot be verified with here.
    Digest(DigestAlgorithm),
    /// A digest algorithm this crate does not know.
    UnknownDigest(ObjectId),
    /// An RSA key size outside what the crypto provider verifies (1024 to
    /// 8192 bits, or 2048 to 8192 for some schemes).
    RsaKeySize(u32),
    /// A curve the crypto provider does not verify (P-521).
    Curve(Curve),
    /// A curve and digest pairing the crypto provider does not verify.
    CurveDigest {
        /// The curve.
        curve: Curve,
        /// The digest.
        digest: DigestAlgorithm,
    },
    /// A key algorithm that is not verified (Ed25519, Ed448, unknown
    /// curves or algorithms).
    KeyAlgorithm(KeyAlgorithm),
    /// A signature algorithm that is not verified.
    SignatureAlgorithm(SignatureAlgorithm),
    /// RSA-PSS parameters other than MGF1 with the message digest and a
    /// salt as long as the digest.
    PssParameters,
    /// The signature algorithm does not fit the signer's key (an ECDSA
    /// signature from an RSA key, for example).
    KeyAlgorithmMismatch,
    /// The image digest for the signature's algorithm was not supplied to
    /// [`super::verify_certificate_table`].
    ImageDigestUnavailable(DigestAlgorithm),
}

/// Why a signature's cryptography failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BadSignature {
    /// The `messageDigest` authenticated attribute does not equal the hash
    /// of the encoded `SpcIndirectDataContent`: the signed content was
    /// changed after signing.
    MessageDigestMismatch,
    /// No certificate in the blob matches the SignerInfo's signer
    /// identifier.
    SignerCertificateNotFound,
    /// The signature over the authenticated attributes does not verify with
    /// the signer certificate's key.
    SignatureInvalid,
}

/// The cryptographic check of one SignerInfo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureCheck {
    /// The `messageDigest` attribute matches the signed content, and the
    /// signature over the authenticated attributes verifies with the signer
    /// certificate's key.
    Valid,
    /// The check failed.
    Invalid(BadSignature),
    /// The check could not be made.
    Unsupported(Unsupported),
    /// The signature could not be parsed, so nothing was checked.
    NotChecked,
}

/// The verdict on one signature, from the checks in this module. The
/// certificate chain is judged by [`super::evaluate_trust`] (#49), and
/// timestamps, expiry and revocation by [`super::evaluate_validity`] (#50).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureStatus {
    /// The signature is cryptographically valid and its digest matches the
    /// image. For a [`SignatureKind::Catalog`] signature, which signs a
    /// trust list rather than an image, it means only that the signature
    /// over the catalog's CTL is cryptographically valid (`digest_match`
    /// is `None`): a member file is catalog-signed only when a valid
    /// catalog also lists its digest (see [`crate::catalog`]).
    Valid,
    /// The signature is cryptographically valid, but the image digest it
    /// signs does not match the file: the file was changed after signing.
    DigestMismatch,
    /// The signature is cryptographically valid and its digest matches the
    /// best-effort digest of an image whose layout departs from the
    /// Authenticode specification (#47): data after the certificate table,
    /// a misaligned table, overlapping sections and so on. Such a match is
    /// not authoritative (bytes can be moved across the certificate table
    /// without changing it), so it is **never** treated as valid; the flat
    /// hash is the file's identity.
    NonConformantImage,
    /// The signature's cryptography failed.
    BadSignature(BadSignature),
    /// The signature uses a broken digest (MD2, MD5). Parsed and reported,
    /// never trusted.
    WeakAlgorithm(DigestAlgorithm),
    /// The signature could not be verified.
    Unsupported(Unsupported),
    /// The signature could not be parsed.
    Malformed(SignatureError),
}

impl SignatureStatus {
    /// Whether the status is [`SignatureStatus::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Where a signature was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureKind {
    /// A `WIN_CERTIFICATE` entry's own SignedData.
    Embedded,
    /// A SignedData in another signature's `szOID_NESTED_SIGNATURE`
    /// (1.3.6.1.4.1.311.2.4.1) unauthenticated attribute.
    Nested,
    /// The signature of a catalog file (#51, [`crate::catalog`]): a
    /// SignedData over a certificate trust list of member digests.
    Catalog,
    /// A script's embedded signature block (#52, [`crate::script`]): a
    /// SignedData whose indirect data is `SPC_SIPINFO`, signing the digest
    /// a script subject interface package computes over the text.
    Script,
}

/// The `SpcStatementType` authenticated attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementType {
    /// Individual code signing (1.3.6.1.4.1.311.2.1.21).
    Individual,
    /// Commercial code signing (1.3.6.1.4.1.311.2.1.22).
    Commercial,
    /// Neither, or both, of the above.
    Other,
}

/// How a SignerInfo names its certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignerIdentifier {
    /// `IssuerAndSerialNumber`.
    IssuerAndSerial {
        /// The issuer `Name`, DER-encoded.
        issuer: Vec<u8>,
        /// The serial number's INTEGER content octets, as encoded.
        serial: Vec<u8>,
    },
    /// `[0] SubjectKeyIdentifier`.
    SubjectKeyId(Vec<u8>),
}

/// The signer attributes that publisher rules use. Present on a
/// [`SignatureInfo`] only when they can be relied on, or when the
/// `tolerate_digest_mismatch` knob exposes them as untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerAttributes {
    /// `SpcSpOpusInfo.programName`.
    pub program_name: Option<String>,
    /// `SpcSpOpusInfo.moreInfo`, when it is a URL.
    pub more_info_url: Option<String>,
    /// `SpcStatementType`.
    pub statement_type: Option<StatementType>,
    /// The `signingTime` attribute, in seconds since the Unix epoch (UTC).
    /// The signer's own claim; a trusted time comes from a timestamp (#50).
    pub signing_time: Option<i64>,
    /// The signer certificate: an index into
    /// [`SignatureInfo::certs_in_blob`]. Chain building is #49.
    pub signer_cert: usize,
    /// The signed metadata attributes (#52), on any signature: read only
    /// and informational for PE files, and the version-like identity of
    /// scripts and other files without a version resource.
    pub signed_metadata: SignedMetadata,
}

/// The signed metadata authenticated attributes
/// (`szOID_SIGNED_ATTRIBUTE_*`, 1.3.6.1.4.1.311.2.7.1 to .10), which give
/// files without a version resource version-like identity. Signers encode
/// each as a UTF8String. A field is `Some` only when its attribute is
/// present and decodes exactly (see
/// [`SignatureWarning::SignedMetadataUnreadable`]); an attribute that
/// appears twice makes the signature [`SignatureStatus::Malformed`].
///
/// These are the signer's claims, covered by the signature: they can be
/// trusted only as far as the signer is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
pub struct SignedMetadata {
    /// .1 `InternalName`.
    pub internal_name: Option<String>,
    /// .2 `FileVersion`.
    pub file_version: Option<String>,
    /// .3 `FileDescription`.
    pub file_description: Option<String>,
    /// .4 `Product`.
    pub product: Option<String>,
    /// .5 `ProductVersion`.
    pub product_version: Option<String>,
    /// .6 `OriginalFilename`.
    pub original_filename: Option<String>,
    /// .7 `Language`.
    pub language: Option<String>,
    /// .8 `Author`.
    pub author: Option<String>,
    /// .9 `PublishTime`, as the signer wrote it. Not parsed: it is the
    /// signer's claim, and a trusted time comes from a timestamp (#50).
    pub publish_time: Option<String>,
    /// .10 `SourceURL`.
    pub source_url: Option<String>,
}

impl SignedMetadata {
    /// The field for the attribute whose final OID arc is `arc` (1 to 10).
    pub(crate) fn field_mut(&mut self, arc: u8) -> Option<&mut Option<String>> {
        Some(match arc {
            1 => &mut self.internal_name,
            2 => &mut self.file_version,
            3 => &mut self.file_description,
            4 => &mut self.product,
            5 => &mut self.product_version,
            6 => &mut self.original_filename,
            7 => &mut self.language,
            8 => &mut self.author,
            9 => &mut self.publish_time,
            10 => &mut self.source_url,
            _ => return None,
        })
    }

    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A page hash table: the one an `SpcSerializedObject` moniker in a
/// signature carries, or one built from a file ([`super::page`]). Check a
/// signed one with [`super::verify_signature_page_hashes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHashes {
    /// SHA-1 (version 1, 1.3.6.1.4.1.311.2.3.1) or SHA-256 (version 2,
    /// 1.3.6.1.4.1.311.2.3.2).
    pub algorithm: HashAlgorithm,
    /// The table: `(u32 file offset, digest)` records, little-endian.
    pub table: Vec<u8>,
}

impl PageHashes {
    /// The `(file offset, digest)` records of the table.
    pub fn entries(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.table
            .chunks_exact(4 + self.algorithm.digest_len())
            .filter_map(|record| {
                let (offset, digest) = record.split_first_chunk::<4>()?;
                Some((u32::from_le_bytes(*offset), digest))
            })
    }
}

/// The kind of a timestamp carried in an unauthenticated attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampKind {
    /// A legacy Authenticode timestamp: a PKCS#9 countersignature
    /// (1.2.840.113549.1.9.6).
    CounterSignature,
    /// An RFC 3161 timestamp token (1.3.6.1.4.1.311.3.3.1, or
    /// 1.2.840.113549.1.9.16.2.14).
    Rfc3161,
}

/// A timestamp found on a signature. [`super::verify_timestamps`] parses
/// and verifies it (#50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampToken {
    /// Which attribute it came from.
    pub kind: TimestampKind,
    /// The attribute value, DER-encoded.
    pub der: Vec<u8>,
}

/// Why a signature cannot be used for an OS-native code integrity signer
/// rule. A rule compiled from such a signer would silently never match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OsCiIssue {
    /// The signer key is not RSA (OS code integrity rejects ECC signers).
    NotRsa(KeyAlgorithm),
    /// The RSA key is larger than 4096 bits.
    RsaKeyTooLarge(u32),
    /// The signature uses a broken digest (MD2, MD5).
    WeakDigest(DigestAlgorithm),
    /// The signer key is not known: the signature did not parse, or no
    /// signer certificate was found.
    SignerUnknown,
}

/// Something unusual about one signature that does not by itself change its
/// status.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignatureWarning {
    /// Bytes follow the SignedData inside its `WIN_CERTIFICATE` entry. A
    /// few zero bytes of padding are normal and not reported; anything else
    /// is unsigned data hidden in a signed file.
    TrailingData {
        /// How many bytes.
        len: usize,
        /// Whether they are all zero.
        all_zero: bool,
    },
    /// The image or signer digest is SHA-1, which is not collision
    /// resistant. The signature loses primary selection to any SHA-2 one.
    Sha1Digest,
    /// The signer's RSA key is smaller than 2048 bits. It still verifies,
    /// for old files, but ADR 0008 sets 2048 bits as the floor for trust.
    SmallRsaKey(u32),
    /// The SignerInfo's digest algorithm differs from the indirect data's.
    /// Each is checked with its own algorithm.
    DigestAlgorithmsDiffer,
    /// The SignedData's `digestAlgorithms` set does not list the signer's
    /// digest algorithm.
    SignerDigestNotListed,
    /// The SignerInfo version does not match its signer identifier form (1
    /// for issuer and serial, 3 for a key identifier).
    SignerVersionMismatch(u32),
    /// More than one certificate matches the signer identifier; the first
    /// is used.
    AmbiguousSignerCertificate,
    /// A certificate in the blob is valid DER but not a certificate this
    /// crate can read (an unexpected structure, or SPKI parameters that are
    /// not allowed for its key). It is kept in
    /// [`SignatureInfo::certs_in_blob`] but cannot be the signer. Invalid
    /// DER in any certificate makes the whole signature
    /// [`SignatureStatus::Malformed`] instead.
    UnparseableCertificate(usize),
    /// The blob holds more than [`super::MAX_CERTIFICATES`] certificates;
    /// the rest were ignored.
    TooManyCertificates,
    /// A `CertificateChoices` entry that is not an X.509 certificate was
    /// skipped.
    NonX509Certificate,
    /// An authenticated attribute of an unknown type was ignored.
    UnknownAuthenticatedAttribute(ObjectId),
    /// An unauthenticated attribute of an unknown type was ignored.
    UnknownUnauthenticatedAttribute(ObjectId),
    /// A text field was longer than 4096 characters and was cut.
    TextTruncated,
    /// A `SpcString` or `SpcLink` used a form this crate does not read
    /// (a moniker or file link as `moreInfo`, for example).
    UnreadLinkForm,
    /// The page hash moniker's table is not a whole number of records, or
    /// its structure is not the expected one. It was dropped.
    PageHashesMalformed,
    /// A nested signature was not parsed because it is deeper than
    /// [`super::MAX_NESTING_DEPTH`].
    NestingTooDeep,
    /// A nested signature or timestamp was not parsed because a limit was
    /// reached ([`super::MAX_SIGNATURES`] signatures, or
    /// [`super::MAX_TIMESTAMPS`] timestamps per signature).
    LimitReached,
    /// More than [`super::MAX_WARNINGS`] warnings; the rest were dropped.
    WarningsTruncated,
    /// A signed metadata attribute (1.3.6.1.4.1.311.2.7.1 to .10) whose
    /// value is not a string, does not decode exactly, or is longer than
    /// 4096 characters. It is left out of [`SignedMetadata`], so no rule can
    /// match a partial or replaced value.
    SignedMetadataUnreadable(ObjectId),
}

/// One Authenticode signature: an embedded SignedData, a nested one, or a
/// catalog's ([`SignatureKind::Catalog`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    /// Position in [`SignatureReport::signatures`]: embedded signatures in
    /// table order, each followed by its nested signatures, depth first.
    pub index: usize,
    /// How many signatures the report holds.
    pub total: usize,
    /// Where the signature was found.
    pub kind: SignatureKind,
    /// The `WIN_CERTIFICATE` entry it came from, an index into
    /// [`SignatureReport::entries`]. 0 for a catalog signature, which has
    /// no entry.
    pub entry: usize,
    /// For a nested signature, the index of the signature that carries it.
    pub parent: Option<usize>,
    /// 0 for an embedded signature, 1 and up for nested ones.
    pub depth: u8,
    /// The image digest algorithm (`SpcIndirectDataContent.messageDigest`).
    /// For a [`SignatureKind::Catalog`] signature, the SignerInfo's digest
    /// algorithm, the one that hashes the CTL (its `messageDigest`); not
    /// any member's digest algorithm.
    pub digest_alg: Option<DigestAlgorithm>,
    /// The image digest the signature signs. `None` for a catalog
    /// signature.
    pub signed_image_digest: Option<Vec<u8>>,
    /// The SignerInfo's digest algorithm, used for the `messageDigest`
    /// attribute and the signature.
    pub signer_digest_alg: Option<DigestAlgorithm>,
    /// The SignerInfo's signature algorithm.
    pub sig_alg: Option<SignatureAlgorithm>,
    /// The signer certificate's key algorithm, if the certificate was found.
    pub key_alg: Option<KeyAlgorithm>,
    /// The signer key's size in bits (the RSA modulus, or the curve size).
    pub key_bits: Option<u32>,
    /// Whether the signed image digest equals the file's Authenticode
    /// digest under the same algorithm. `None` if it could not be computed,
    /// and always `None` for a catalog signature, which signs no image.
    pub digest_match: Option<bool>,
    /// The cryptographic check.
    pub signature_valid: SignatureCheck,
    /// The overall verdict.
    pub status: SignatureStatus,
    /// The signer attributes publisher rules use. `Some` only when
    /// [`Self::status`] is [`SignatureStatus::Valid`], or when it is
    /// [`SignatureStatus::DigestMismatch`] and the
    /// `tolerate_digest_mismatch` knob is on; in the second case
    /// [`Self::untrusted_signer_attrs`] is `true`.
    pub signer: Option<SignerAttributes>,
    /// `true` when [`Self::signer`] is reported only because of
    /// `tolerate_digest_mismatch`: rules must not trust it, and should fall
    /// back to hash identity.
    pub untrusted_signer_attrs: bool,
    /// How the SignerInfo names its certificate. Attacker-controlled; it is
    /// not covered by the signature.
    pub signer_id: Option<SignerIdentifier>,
    /// Every certificate in the SignedData, DER-encoded, in blob order (at
    /// most [`super::MAX_CERTIFICATES`]).
    pub certs_in_blob: Vec<Vec<u8>>,
    /// The `SpcPeImageData` flags octet (bit 7 is `includeResources`).
    pub pe_image_flags: Option<u8>,
    /// The page hash table, if the signature carries one (#47).
    pub page_hashes: Option<PageHashes>,
    /// Timestamps in the unauthenticated attributes, verified by
    /// [`super::verify_timestamps`] (#50).
    pub timestamp_tokens: Vec<TimestampToken>,
    /// The SignerInfo's signature value (`encryptedDigest`): what a
    /// timestamp covers. Empty if the signature did not parse.
    pub signature_value: Vec<u8>,
    /// Why the signer cannot back an OS-native code integrity signer rule;
    /// empty when it can.
    pub os_ci_issues: Vec<OsCiIssue>,
    /// Anything unusual that does not change the status.
    pub warnings: Vec<SignatureWarning>,
}

impl SignatureInfo {
    /// Whether an OS-native code integrity signer rule can use this signer:
    /// an RSA key of at most 4096 bits and no MD2 or MD5.
    #[must_use]
    pub fn os_ci_compatible(&self) -> bool {
        self.os_ci_issues.is_empty()
    }
}

/// Why a signature could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignatureError {
    /// The DER encoding is invalid.
    Asn1(Asn1Error),
    /// The outer ContentInfo is not `signedData`.
    NotSignedData(ObjectId),
    /// The signed content type is not `SPC_INDIRECT_DATA_OBJID`.
    NotIndirectData(ObjectId),
    /// The signed content type of a catalog is not `szOID_CTL`
    /// (1.3.6.1.4.1.311.10.1).
    NotCatalog(ObjectId),
    /// The indirect data is not `SPC_PE_IMAGE_DATA_OBJID`, so it does not
    /// sign a PE image.
    NotPeImageData(ObjectId),
    /// The indirect data is not `SPC_SIPINFO_OBJID`, so it does not sign a
    /// script (#52).
    NotSipInfo(ObjectId),
    /// The `SpcSipInfo` value is malformed: its GUID is not 16 bytes.
    SipInfo,
    /// The `SpcSipInfo` names a subject interface package other than the
    /// one for the script's format (a VBScript signature in a JScript
    /// file, say), so the signed digest is not of this kind of file.
    SipMismatch,
    /// The SignedData has no signed content.
    MissingContent,
    /// Authenticode requires exactly one SignerInfo.
    SignerCount(usize),
    /// The SignerInfo has no authenticated attributes.
    MissingAuthenticatedAttributes,
    /// A required authenticated attribute (`contentType` or
    /// `messageDigest`) is missing.
    MissingAttribute(ObjectId),
    /// An authenticated attribute appears more than once.
    DuplicateAttribute(ObjectId),
    /// An authenticated attribute that must have exactly one value has
    /// another number of values.
    AttributeValueCount(ObjectId),
    /// The `contentType` attribute does not name the signed content type
    /// (`SPC_INDIRECT_DATA_OBJID`, or `szOID_CTL` for a catalog).
    ContentTypeMismatch(ObjectId),
    /// The signature algorithm implies a digest other than the SignerInfo's
    /// digest algorithm.
    InconsistentDigestAlgorithms,
    /// The signed image digest is not as long as its algorithm's output.
    DigestLength,
    /// An algorithm identifier has parameters where none are allowed, or
    /// invalid ones.
    AlgorithmParameters,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::NotSignedData(o) => write!(f, "content type {o} is not signedData"),
            Self::NotIndirectData(o) => {
                write!(f, "signed content type {o} is not SPC_INDIRECT_DATA")
            }
            Self::NotCatalog(o) => write!(f, "signed content type {o} is not szOID_CTL"),
            Self::NotPeImageData(o) => write!(f, "indirect data type {o} is not SPC_PE_IMAGE_DATA"),
            Self::NotSipInfo(o) => write!(f, "indirect data type {o} is not SPC_SIPINFO"),
            Self::SipInfo => f.write_str("the SpcSipInfo GUID is not 16 bytes"),
            Self::SipMismatch => {
                f.write_str("the SpcSipInfo names another format's subject interface package")
            }
            Self::MissingContent => f.write_str("the SignedData has no content"),
            Self::SignerCount(n) => write!(f, "{n} SignerInfos; Authenticode requires exactly one"),
            Self::MissingAuthenticatedAttributes => f.write_str("no authenticated attributes"),
            Self::MissingAttribute(o) => write!(f, "missing authenticated attribute {o}"),
            Self::DuplicateAttribute(o) => write!(f, "authenticated attribute {o} appears twice"),
            Self::AttributeValueCount(o) => write!(f, "attribute {o} must have exactly one value"),
            Self::ContentTypeMismatch(o) => {
                write!(
                    f,
                    "contentType attribute {o} does not name the signed content"
                )
            }
            Self::InconsistentDigestAlgorithms => {
                f.write_str("the signature algorithm's digest differs from the signer's")
            }
            Self::DigestLength => f.write_str("the signed image digest has the wrong length"),
            Self::AlgorithmParameters => f.write_str("invalid algorithm parameters"),
        }
    }
}

impl std::error::Error for SignatureError {}

impl From<Asn1Error> for SignatureError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

/// Why the certificate table as a whole could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateTableError {
    /// The PE parser did not accept the security directory as a
    /// certificate table ([`crate::pe::PeInfo::certificate_table_issue`]).
    Rejected(Option<WarningKind>),
    /// The table is larger than [`super::MAX_CERTIFICATE_TABLE_SIZE`].
    TooLarge(u64),
    /// The first `WIN_CERTIFICATE` entry's `dwLength` is below 8 or runs
    /// past the table, so no entry could be read.
    Malformed {
        /// File offset of the entry.
        offset: u64,
    },
}

/// Why a signed file is not validly signed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidReason {
    /// The certificate table could not be read.
    CertificateTable(CertificateTableError),
    /// No signature is valid. This is the status of the first one.
    Signature(SignatureStatus),
}

/// The signing state of a file.
///
/// Catalog signing (`CatalogValid`, from [`crate::catalog`] lookups) is
/// still to come (#51).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningState {
    /// No embedded signature.
    Unsigned,
    /// At least one signature is valid (see [`SignatureReport::primary`]).
    Valid,
    /// The file carries a signature, but none is valid.
    Invalid(InvalidReason),
}

/// One `WIN_CERTIFICATE` entry of the certificate table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateEntry {
    /// File offset of the entry.
    pub offset: u64,
    /// `dwLength`, including the 8-byte header.
    pub length: u32,
    /// `wRevision`.
    pub revision: u16,
    /// `wCertificateType`.
    pub certificate_type: u16,
    /// The index of its embedded signature in
    /// [`SignatureReport::signatures`], if it is a PKCS#7 entry that was
    /// read.
    pub signature: Option<usize>,
}

/// Something unusual about the certificate table or the image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportWarning {
    /// An entry whose revision is not 0x0100 or 0x0200, or whose type is
    /// not `WIN_CERT_TYPE_PKCS_SIGNED_DATA` (2), was recorded and skipped.
    UnknownEntry {
        /// The entry's index in [`SignatureReport::entries`].
        entry: usize,
    },
    /// An entry's `dwLength` is below 8 or runs past the table. Reading
    /// stopped there.
    BadEntryLength {
        /// File offset of the entry.
        offset: u64,
        /// Its `dwLength`.
        length: u32,
    },
    /// Non-zero bytes in the padding between or after entries. They are
    /// not covered by any hash or signature.
    UnexpectedTableData {
        /// File offset of the first such byte.
        offset: u64,
    },
    /// More than [`super::MAX_CERTIFICATE_ENTRIES`] entries; the rest were
    /// not read.
    TooManyEntries,
    /// [`super::MAX_SIGNATURES`] signatures were read; any others were not.
    TooManySignatures,
    /// The image layout is not one the Authenticode specification
    /// describes, so its digest is a best effort (#47) and its flat hash is
    /// the identity to use.
    NonConformantImage,
    /// `tolerate_digest_mismatch` exposed the signer attributes of this
    /// signature, marked untrusted. Recorded for audit.
    DigestMismatchTolerated {
        /// The signature's index.
        signature: usize,
    },
}

/// Options for signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyOptions {
    /// When `true`, the signer attributes of a signature whose only problem
    /// is [`SignatureStatus::DigestMismatch`] are still reported, marked
    /// [`SignatureInfo::untrusted_signer_attrs`], so rules can fall back to
    /// hash identity. The file stays [`SigningState::Invalid`]. Default
    /// `false`. Every use is recorded as
    /// [`ReportWarning::DigestMismatchTolerated`], and the setting itself is
    /// echoed in [`SignatureReport::tolerate_digest_mismatch`].
    pub tolerate_digest_mismatch: bool,
}

/// Every embedded and nested signature of a PE image, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureReport {
    /// The `WIN_CERTIFICATE` entries read, in table order.
    pub entries: Vec<CertificateEntry>,
    /// Every signature, in [`SignatureInfo::index`] order.
    pub signatures: Vec<SignatureInfo>,
    /// The primary signature: the first valid one with the strongest digest
    /// (SHA-256 or better beats SHA-1). `None` if none is valid.
    pub primary: Option<usize>,
    /// The file's signing state.
    pub signing_state: SigningState,
    /// The [`VerifyOptions::tolerate_digest_mismatch`] setting used, for
    /// audit.
    pub tolerate_digest_mismatch: bool,
    /// The image's Authenticode layout status (#47).
    pub image_status: AuthenticodeStatus,
    /// Anything unusual about the table or the image.
    pub warnings: Vec<ReportWarning>,
}

impl SignatureReport {
    /// The primary signature, if any.
    #[must_use]
    pub fn primary_signature(&self) -> Option<&SignatureInfo> {
        self.primary.and_then(|i| self.signatures.get(i))
    }
}
