//! Catalog-signed files (#51): catalog parsing, catalog signature checks,
//! the catalog store and its member index.
//!
//! Many OS components and drivers carry no embedded signature. A
//! **catalog file** (`.cat`) signs them instead: a PKCS#7 SignedData whose
//! content is a certificate trust list (CTL, `szOID_CTL`
//! 1.3.6.1.4.1.311.10.1) of member digests. A file is catalog-signed when
//! a catalog whose signature is valid lists its digest, and the catalog's
//! signer is then the file's publisher.
//!
//! - [`parse_catalog`] decodes a catalog file and verifies its signature
//!   with the same machinery as embedded Authenticode signatures (#48): the
//!   strict DER reader, the SignedData decoder, the signer certificate
//!   lookup, the `messageDigest` check over the CTL and the signature over
//!   the authenticated attributes. The result is a [`Catalog`]: the decoded
//!   [`CertificateTrustList`] and a [`SignatureReport`] with one
//!   [`SignatureKind::Catalog`] signature, which
//!   [`crate::authenticode::evaluate_trust`] takes like any other (#49).
//! - [`parse_ctl`] decodes a CTL on its own.
//! - [`CatalogStoreBuilder`] loads catalogs from bytes or from a directory
//!   tree, within [`StoreLimits`], into a [`CatalogStore`] that indexes, by
//!   digest, the members of catalogs whose signature is valid.
//!   [`CatalogStore::lookup`] takes a file's [`FileDigests`] and returns
//!   each catalog that lists it, trusted catalogs first, with the signer's
//!   trust verdict and identity.
//!
//! # Which members are indexed
//!
//! Only members of a catalog whose signature is valid, and of those only
//! members with an `SPC_INDIRECT_DATA` digest under SHA-256 or SHA-1.
//! Members with no digest, or a digest under another algorithm, are kept
//! in the [`CertificateTrustList`] but never indexed. Limits can leave out
//! members that would otherwise be indexed: those past [`MAX_MEMBERS`] in
//! one catalog ([`CertificateTrustList::members_truncated`]) and those past
//! [`StoreLimits::max_members`] in the store
//! ([`CatalogRecord::index_truncated`]). So a lookup that finds nothing does
//! not show that no catalog lists the file; check those flags, and the
//! store's records, before treating a miss as absence.
//!
//! # Member digests
//!
//! A member's `SPC_INDIRECT_DATA` attribute holds its digest and the
//! indirect data type. For a PE member (`SPC_PE_IMAGE_DATA`) the digest is
//! the Authenticode image hash (#47); for any other file it is the hash
//! the file type's subject interface package computes, which for files
//! without one is the flat hash (#46). v1 catalogs
//! (`szOID_CATALOG_LIST_MEMBER`) use SHA-1, v2 catalogs
//! (`szOID_CATALOG_LIST_MEMBER2`) SHA-256; the index takes whatever
//! algorithm each member names. Members are indexed by digest, never by
//! their tag string or `File` name, which the signature covers but which
//! say nothing about the file's content.
//!
//! SHA-1 members are compatibility-only (ADR 0008): a match reports its
//! algorithm, and policy must not let an allow decision rest on a SHA-1
//! match alone (#40).
//!
//! # What a match means
//!
//! A [`CatalogMatch`] says that a catalog whose signature is
//! cryptographically valid lists the file's digest. Whether its signer is
//! trusted is [`CatalogMatch::trusted`], decided by the [`TrustConfig`]
//! given when the catalog was loaded. Catalogs whose signature is not valid
//! (tampered, unsupported, malformed) are recorded with their status but
//! never indexed, so they match nothing. Validity periods, timestamps and
//! revocation are #50, as for embedded signatures.
//!
//! # Not done here yet
//!
//! - The persistent on-disk index, incremental updates from the change
//!   feed (#60), low-priority builds (#65), the `catalog_lookup_enabled`,
//!   `catalog_scope` and `skip_catalog_for_paths` settings and the
//!   authoring helper remain part of #51.
//! - The OS catalog database cross-check (`CryptCATAdmin*`, Windows,
//!   behind `os-trust`) remains part of #51; it needs the Windows API
//!   dependency and unsafe-code allowlist entry that ADR 0011 requires.
//! - Folding catalog matches into a file's signing state (`CatalogValid`)
//!   is the unified file identity record (#55).
//!
//! # Untrusted input
//!
//! Catalog files are attacker-controlled. The same rules as for embedded
//! signatures apply: DER only, typed errors, no panics, no allocation sized
//! by a declared length, and fixed limits: [`MAX_CATALOG_SIZE`],
//! [`MAX_MEMBERS`], [`MAX_ATTRIBUTES`], [`MAX_NAME_VALUES`],
//! [`MAX_VALUE_BYTES`], [`MAX_CTL_WARNINGS`] and [`MAX_DECODED_BYTES`] per
//! catalog, and [`StoreLimits`] for a store. The trust list is decoded
//! before its signature is checked, so [`MAX_DECODED_BYTES`] bounds the
//! memory an unsigned or forged catalog can take. The `fuzz_ctl` fuzz target covers parsing,
//! loading and lookup.

#![forbid(unsafe_code)]

mod ctl;
mod store;

use std::fmt;

pub use ctl::{
    CatalogMember, CertificateTrustList, CtlError, CtlWarning, MAX_ATTRIBUTES, MAX_CTL_WARNINGS,
    MAX_DECODED_BYTES, MAX_MEMBERS, MAX_NAME_VALUES, MAX_VALUE_BYTES, MemberDigest, MemberTag,
    NameValue, NameValueData, SubjectAlgorithm, parse_ctl,
};
pub use store::{
    CatalogMatch, CatalogRecord, CatalogSigner, CatalogSource, CatalogStatus, CatalogStore,
    CatalogStoreBuilder, DigestKind, FileDigests, LoadError, LoadReport, LookupResult,
    MAX_LOAD_ERRORS, MAX_MATCHES, StoreLimits,
};

use crate::authenticode::asn1;
use crate::authenticode::pkcs7::{self, Warnings};
use crate::authenticode::verify::{check_signature, find_signer_cert, os_ci_issues};
use crate::authenticode::{
    AuthenticodeStatus, BadSignature, DigestAlgorithm, InvalidReason, KeyAlgorithm, SignatureCheck,
    SignatureError, SignatureInfo, SignatureKind, SignatureReport, SignatureStatus,
    SignatureWarning, SignerAttributes, SigningState, TrustConfig, TrustReport, evaluate_trust,
};
use crate::hash::{AlgorithmSet, Digest, HashAlgorithm, hash_bytes};

/// The largest catalog file read: 64 MiB.
pub const MAX_CATALOG_SIZE: u64 = 64 * 1024 * 1024;

/// Why a catalog file could not be read at all.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatalogError {
    /// The file is larger than [`MAX_CATALOG_SIZE`].
    TooLarge(u64),
    /// The SignedData around the CTL could not be decoded (including a
    /// content type other than `szOID_CTL`,
    /// [`SignatureError::NotCatalog`]).
    Envelope(SignatureError),
    /// The CTL could not be decoded.
    Ctl(CtlError),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "catalog of {n} bytes exceeds {MAX_CATALOG_SIZE}"),
            Self::Envelope(e) => write!(f, "catalog signature: {e}"),
            Self::Ctl(e) => write!(f, "catalog trust list: {e}"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Something unusual about a catalog file as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatalogWarning {
    /// Bytes follow the SignedData. They are not signed.
    TrailingData {
        /// How many bytes.
        len: usize,
    },
    /// The signer carries this many nested signatures (counted up to the
    /// collection limit). They are checked as DER (tags, lengths and the
    /// primitive encodings [`parse_catalog`] checks everywhere) but not
    /// decoded or verified: only the catalog's own signature counts.
    NestedSignaturesIgnored(usize),
}

/// A parsed catalog file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    /// The catalog's identity: the SHA-256 of the whole file.
    pub id: Digest,
    /// The file's size in bytes.
    pub size: u64,
    /// The decoded trust list.
    pub ctl: CertificateTrustList,
    /// The catalog's signature, as one [`SignatureKind::Catalog`]
    /// signature. Pass it to [`crate::authenticode::evaluate_trust`] for
    /// the signer's chain, trust and identity (with the member file's
    /// version resource, for the file-level identity), or use
    /// [`Self::trust`].
    ///
    /// Unlike a PE report, it has no `WIN_CERTIFICATE` entries, and its
    /// `image_status` is always conformant: a catalog has no image layout.
    pub signatures: SignatureReport,
    /// Anything unusual about the file.
    pub warnings: Vec<CatalogWarning>,
}

impl Catalog {
    /// The catalog's signature.
    #[must_use]
    pub fn signature(&self) -> Option<&SignatureInfo> {
        self.signatures.signatures.first()
    }

    /// Whether the signature is cryptographically valid. Says nothing about
    /// whether the signer is trusted.
    #[must_use]
    pub fn signature_valid(&self) -> bool {
        self.signatures.primary.is_some()
    }

    /// The signer's chain and trust under `config`, with signer-level
    /// identity (no file version resource).
    #[must_use]
    pub fn trust(&self, config: &TrustConfig) -> TrustReport {
        evaluate_trust(&self.signatures, config, None)
    }

    /// Every member whose digest is `digest` under `alg`.
    pub fn members_with_digest<'a>(
        &'a self,
        alg: DigestAlgorithm,
        digest: &'a [u8],
    ) -> impl Iterator<Item = &'a CatalogMember> + 'a {
        self.ctl.members.iter().filter(move |m| {
            m.digest
                .as_ref()
                .is_some_and(|d| d.alg == alg && d.digest == digest)
        })
    }
}

/// Parses a catalog file and verifies its signature.
///
/// Fails only when the file is too large, or its SignedData or CTL cannot
/// be decoded. A catalog that decodes but whose signature does not verify
/// is returned, with the reason in [`Catalog::signatures`].
///
/// Every element of the SignedData, including the parts no decoder reads
/// (nested signatures), must be DER as far as tags and lengths go, and
/// its INTEGER, BOOLEAN, NULL and OBJECT IDENTIFIER encodings must be
/// valid: an INTEGER non-empty, a BOOLEAN `00` or `ff`, a NULL empty, an
/// OBJECT IDENTIFIER well formed. (INTEGERs the CTL decoder reads must also
/// be minimal; certificate serial numbers, as elsewhere in the crate, need
/// not be.)
pub fn parse_catalog(bytes: &[u8]) -> Result<Catalog, CatalogError> {
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if size > MAX_CATALOG_SIZE {
        return Err(CatalogError::TooLarge(size));
    }
    let (envelope, ctl_tlv, trailing) = pkcs7::parse_envelope(
        bytes,
        0,
        ctl::oid::CTL,
        SignatureError::NotCatalog,
        |content, _| Ok(*content),
    )
    .map_err(CatalogError::Envelope)?;
    let ctl = ctl::parse_ctl_tlv(&ctl_tlv).map_err(CatalogError::Ctl)?;
    // Parts the decoders skip without reading (nested signatures on the
    // signer, which the PE walker checks by parsing them) are still held
    // to DER: check the whole element once.
    let mut whole = asn1::Reader::new(bytes, 0);
    whole
        .read(asn1::tag::SEQUENCE)
        .and_then(|tlv| validate_strict(&tlv))
        .map_err(|e| CatalogError::Envelope(e.into()))?;

    let mut warnings = Vec::new();
    if !trailing.is_empty() {
        warnings.push(CatalogWarning::TrailingData {
            len: trailing.len(),
        });
    }
    if !envelope.signer.nested.is_empty() {
        warnings.push(CatalogWarning::NestedSignaturesIgnored(
            envelope.signer.nested.len(),
        ));
    }

    let info = check(&envelope, ctl_tlv.content);
    let valid = info.status.is_valid();
    let signing_state = if valid {
        SigningState::Valid
    } else {
        SigningState::Invalid(InvalidReason::Signature(info.status.clone()))
    };
    let signatures = SignatureReport {
        entries: Vec::new(),
        signatures: vec![info],
        primary: valid.then_some(0),
        signing_state,
        tolerate_digest_mismatch: false,
        image_status: AuthenticodeStatus::Conformant,
        warnings: Vec::new(),
    };
    // `hash_bytes` always returns the digests it was asked for; the error
    // only keeps this free of a panic path.
    let id = hash_bytes(bytes, AlgorithmSet::SHA256)
        .get(HashAlgorithm::Sha256)
        .cloned()
        .ok_or(CatalogError::TooLarge(size))?;
    Ok(Catalog {
        id,
        size,
        ctl,
        signatures,
        warnings,
    })
}

/// [`asn1::validate`], plus a check of each primitive INTEGER, BOOLEAN,
/// NULL and OBJECT IDENTIFIER's content. Iterative, at most
/// [`asn1::MAX_DEPTH`] levels deep, like [`asn1::validate`].
fn validate_strict(tlv: &asn1::Tlv<'_>) -> Result<(), asn1::Asn1Error> {
    let mut stack: Vec<asn1::Reader<'_>> = Vec::new();
    check_element(tlv, &mut stack)?;
    while let Some(top) = stack.last_mut() {
        if top.is_empty() {
            stack.pop();
            continue;
        }
        let child = top.read_any()?;
        check_element(&child, &mut stack)?;
    }
    Ok(())
}

/// Checks one element for [`validate_strict`]: a primitive's content, or,
/// for a constructed element, pushes a reader over its children.
fn check_element<'a>(
    element: &asn1::Tlv<'a>,
    stack: &mut Vec<asn1::Reader<'a>>,
) -> Result<(), asn1::Asn1Error> {
    use asn1::tag;
    match element.tag {
        tag::INTEGER => asn1::integer_bytes(element).map(|_| ()),
        tag::BOOLEAN => asn1::boolean(element).map(|_| ()),
        tag::OID => asn1::oid_bytes(element).map(|_| ()),
        tag::NULL if !element.content.is_empty() => {
            Err(element.error(asn1::Asn1ErrorKind::InvalidValue))
        }
        constructed if constructed & 0x20 != 0 => {
            if stack.len() >= asn1::MAX_DEPTH {
                return Err(element.error(asn1::Asn1ErrorKind::TooDeep));
            }
            stack.push(element.reader());
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Checks the catalog's SignerInfo over `content`, the CTL's content
/// octets. The signed content has no separate digest to compare (unlike a
/// PE image digest), so the signature check alone decides the status.
fn check(envelope: &pkcs7::Envelope<'_>, content: &[u8]) -> SignatureInfo {
    let mut warnings = Warnings(envelope.warnings.0.clone());
    let signer = &envelope.signer;
    let signer_cert = find_signer_cert(&envelope.certificates, &signer.sid, &mut warnings);
    let signer_alg = signer.digest_alg.as_ref().ok().copied();
    if !envelope.signer_digest_listed {
        warnings.push(SignatureWarning::SignerDigestNotListed);
    }
    if signer_alg == Some(DigestAlgorithm::Sha1) {
        warnings.push(SignatureWarning::Sha1Digest);
    }
    let signature_valid = check_signature(signer, content, signer_cert.as_ref().map(|(_, c)| c));
    let weak = signer_alg.filter(|a| a.is_broken());
    let status = match (weak, &signature_valid) {
        (Some(alg), _) => SignatureStatus::WeakAlgorithm(alg),
        (None, SignatureCheck::Valid) => SignatureStatus::Valid,
        (None, SignatureCheck::Invalid(why)) => SignatureStatus::BadSignature(*why),
        (None, SignatureCheck::Unsupported(why)) => SignatureStatus::Unsupported(why.clone()),
        // `check_signature` never returns this; fail closed if it does.
        (None, SignatureCheck::NotChecked) => {
            SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
        }
    };
    let (key_alg, key_bits) = match &signer_cert {
        Some((_, cert)) => (Some(cert.key_alg.clone()), cert.key_bits),
        None => (None, None),
    };
    if let (Some(KeyAlgorithm::Rsa), Some(bits)) = (&key_alg, key_bits) {
        if bits < 2048 {
            warnings.push(SignatureWarning::SmallRsaKey(bits));
        }
    }
    let os_ci_issues = os_ci_issues(key_alg.as_ref(), key_bits, weak);
    let signer_attrs = match (&status, &signer_cert) {
        (SignatureStatus::Valid, Some((i, _))) => Some(SignerAttributes {
            program_name: signer.opus.program_name.clone(),
            more_info_url: signer.opus.more_info_url.clone(),
            statement_type: signer.statement_type,
            signing_time: signer.signing_time,
            signer_cert: *i,
            signed_metadata: signer.signed_metadata.clone(),
        }),
        _ => None,
    };
    // Every field is spelled out, so a field added to `SignatureInfo`
    // cannot be left at a default here unnoticed.
    SignatureInfo {
        index: 0,
        total: 1,
        kind: SignatureKind::Catalog,
        entry: 0,
        parent: None,
        depth: 0,
        // The signed content's digest is the signer's (`messageDigest`
        // over the CTL), so primary selection and SHA-1 checks rank it.
        digest_alg: signer_alg,
        signed_image_digest: None,
        signer_digest_alg: signer_alg,
        sig_alg: Some(signer.sig_alg.clone()),
        key_alg,
        key_bits,
        digest_match: None,
        signature_valid,
        status,
        signer: signer_attrs,
        untrusted_signer_attrs: false,
        signer_id: Some(signer.sid.clone()),
        certs_in_blob: envelope.certificates.iter().map(|c| c.to_vec()).collect(),
        pe_image_flags: None,
        page_hashes: None,
        timestamp_tokens: signer.timestamps.clone(),
        // What a timestamp on the catalog must imprint (#50).
        signature_value: signer.signature.to_vec(),
        os_ci_issues,
        warnings: warnings.0,
    }
}
