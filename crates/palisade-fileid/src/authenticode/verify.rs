//! Walks the certificate table and verifies every embedded and nested
//! Authenticode signature (#48).

#![forbid(unsafe_code)]

use super::crypto::{self, PublicKey, Scheme, Verified};
use super::hash::{AuthenticodeError, AuthenticodeHashes, HashRanges, image_digests};
use super::pkcs7::{self, CertKey, Certificate, SignedData, Signer, Warnings};
use super::signature::{
    BadSignature, CertificateEntry, CertificateTableError, DigestAlgorithm, InvalidReason,
    KeyAlgorithm, OsCiIssue, ReportWarning, SignatureAlgorithm, SignatureCheck, SignatureInfo,
    SignatureKind, SignatureReport, SignatureStatus, SignatureWarning, SignerAttributes,
    SignerIdentifier, SigningState, Unsupported, VerifyOptions,
};
use crate::hash::{AlgorithmSet, hash_bytes};
use crate::pe::{self, DataDirectoryKind, ParseOptions, PeError, PeInfo};

/// The most `WIN_CERTIFICATE` entries read from one table.
pub const MAX_CERTIFICATE_ENTRIES: usize = 16;
/// The largest certificate table read: 16 MiB.
pub const MAX_CERTIFICATE_TABLE_SIZE: u64 = 16 * 1024 * 1024;
/// The deepest nested signature read: a signature nested in a signature,
/// and so on, at most this many levels below an embedded one.
pub const MAX_NESTING_DEPTH: u8 = 8;
/// The most signatures, embedded and nested, read from one file.
pub const MAX_SIGNATURES: usize = 32;

/// `WIN_CERT_REVISION_1_0` and `WIN_CERT_REVISION_2_0`.
const REVISIONS: [u16; 2] = [0x0100, 0x0200];
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
const PKCS_SIGNED_DATA: u16 = 0x0002;
/// `WIN_CERTIFICATE` header size.
const ENTRY_HEADER: usize = 8;
/// Signers pad each entry to this boundary.
const ENTRY_ALIGNMENT: usize = 8;

/// Parses `data` as a PE image (headers only) and verifies its signatures.
/// Fails only if `data` is not a PE image.
pub fn verify_pe(data: &[u8], options: &VerifyOptions) -> Result<SignatureReport, PeError> {
    let info = pe::parse_with(data, &ParseOptions::metadata_only())?;
    // `data` is the buffer `info` was parsed from, so the length always
    // matches. Should it not, no image digest is available and every
    // signature reports `ImageDigestUnavailable`: never a false `Valid`.
    let image =
        image_digests(data, &info, AlgorithmSet::ALL).unwrap_or_else(|_| AuthenticodeHashes {
            digests: Vec::new(),
            hashed_bytes: 0,
            status: HashRanges::from_pe(&info).status().clone(),
            page_hashes: None,
        });
    Ok(verify_certificate_table(data, &info, &image, options))
}

/// Verifies the signatures of `data`, the image `info` was parsed from,
/// computing its Authenticode digests under every algorithm. Fails only if
/// `data` is not the length `info` was parsed from.
pub fn verify_signatures(
    data: &[u8],
    info: &PeInfo,
    options: &VerifyOptions,
) -> Result<SignatureReport, AuthenticodeError> {
    let image = image_digests(data, info, AlgorithmSet::ALL)?;
    Ok(verify_certificate_table(data, info, &image, options))
}

/// Verifies the signatures in the certificate table of `data`, comparing
/// each signed image digest with `image`, the file's Authenticode digests
/// (from [`super::authenticode_hashes`] or a [`super::RangeHasher`]). A signature
/// whose digest algorithm is missing from `image` is reported as
/// [`Unsupported::ImageDigestUnavailable`].
#[must_use]
pub fn verify_certificate_table(
    data: &[u8],
    info: &PeInfo,
    image: &AuthenticodeHashes,
    options: &VerifyOptions,
) -> SignatureReport {
    let mut report = SignatureReport {
        entries: Vec::new(),
        signatures: Vec::new(),
        primary: None,
        signing_state: SigningState::Unsigned,
        tolerate_digest_mismatch: options.tolerate_digest_mismatch,
        image_status: image.status.clone(),
        warnings: Vec::new(),
    };
    if !image.status.is_conformant() {
        report.warnings.push(ReportWarning::NonConformantImage);
    }

    let table_error = match read_table(data, info) {
        Ok(Some((table, offset))) => walk_table(table, offset, image, options, &mut report),
        Ok(None) => None,
        Err(e) => Some(e),
    };

    let total = report.signatures.len();
    for sig in &mut report.signatures {
        sig.total = total;
    }
    report.primary = select_primary(&report.signatures);
    report.signing_state = match (report.primary, table_error, report.signatures.first()) {
        (Some(_), _, _) => SigningState::Valid,
        (None, _, Some(first)) => {
            SigningState::Invalid(InvalidReason::Signature(first.status.clone()))
        }
        (None, Some(e), None) => SigningState::Invalid(InvalidReason::CertificateTable(e)),
        (None, None, None) => SigningState::Unsigned,
    };
    report
}

/// The certificate table's bytes and file offset, `None` if the image has
/// none.
fn read_table<'a>(
    data: &'a [u8],
    info: &PeInfo,
) -> Result<Option<(&'a [u8], u64)>, CertificateTableError> {
    let Some(table) = info.certificate_table else {
        let declared = info
            .data_directories
            .get(DataDirectoryKind::Security.index())
            .is_some_and(|entry| entry.size != 0);
        return if declared {
            Err(CertificateTableError::Rejected(
                info.certificate_table_issue.clone(),
            ))
        } else {
            Ok(None)
        };
    };
    if table.size > MAX_CERTIFICATE_TABLE_SIZE {
        return Err(CertificateTableError::TooLarge(table.size));
    }
    let bytes = usize::try_from(table.offset)
        .ok()
        .zip(usize::try_from(table.size).ok())
        .and_then(|(offset, size)| data.get(offset..offset.checked_add(size)?))
        .ok_or(CertificateTableError::Rejected(None))?;
    Ok(Some((bytes, table.offset)))
}

fn file_offset(table_offset: u64, pos: usize) -> u64 {
    table_offset.saturating_add(u64::try_from(pos).unwrap_or(u64::MAX))
}

/// Reads every `WIN_CERTIFICATE` entry and verifies the PKCS#7 ones. Returns
/// an error only if the table is malformed before any entry could be read.
fn walk_table(
    table: &[u8],
    table_offset: u64,
    image: &AuthenticodeHashes,
    options: &VerifyOptions,
    report: &mut SignatureReport,
) -> Option<CertificateTableError> {
    let mut pos = 0_usize;
    let mut malformed = None;
    while pos < table.len() {
        let rest = table.get(pos..).unwrap_or_default();
        if rest.len() < ENTRY_HEADER {
            if pos == 0 {
                // A table too short for even one entry header.
                malformed = Some(CertificateTableError::Malformed {
                    offset: file_offset(table_offset, pos),
                });
            } else if rest.iter().any(|b| *b != 0) {
                report.warnings.push(ReportWarning::UnexpectedTableData {
                    offset: file_offset(table_offset, pos),
                });
            }
            break;
        }
        if report.entries.len() >= MAX_CERTIFICATE_ENTRIES {
            report.warnings.push(ReportWarning::TooManyEntries);
            break;
        }
        let word = |at: usize| {
            rest.get(at..at + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
        };
        let half = |at: usize| {
            rest.get(at..at + 2)
                .and_then(|b| b.try_into().ok())
                .map(u16::from_le_bytes)
        };
        let (Some(length), Some(revision), Some(certificate_type)) = (word(0), half(4), half(6))
        else {
            break;
        };
        let offset = file_offset(table_offset, pos);
        let body = usize::try_from(length)
            .ok()
            .filter(|len| *len >= ENTRY_HEADER)
            .and_then(|len| rest.get(ENTRY_HEADER..len));
        let Some(body) = body else {
            report
                .warnings
                .push(ReportWarning::BadEntryLength { offset, length });
            // The walk stops here, so any later signature is unreadable.
            // With no signature read, the file is not "unsigned": its
            // table is corrupt.
            if report.signatures.is_empty() {
                malformed = Some(CertificateTableError::Malformed { offset });
            }
            break;
        };
        let entry_index = report.entries.len();
        report.entries.push(CertificateEntry {
            offset,
            length,
            revision,
            certificate_type,
            signature: None,
        });
        if REVISIONS.contains(&revision) && certificate_type == PKCS_SIGNED_DATA {
            if report.signatures.len() < MAX_SIGNATURES {
                let base = pos.saturating_add(ENTRY_HEADER);
                let index = report.signatures.len();
                if let Some(entry) = report.entries.get_mut(entry_index) {
                    entry.signature = Some(index);
                }
                let mut walker = Walker {
                    image,
                    options,
                    report,
                    entry: entry_index,
                };
                walker.signature(body, base, SignatureKind::Embedded, None, 0);
            } else if !report.warnings.contains(&ReportWarning::TooManySignatures) {
                report.warnings.push(ReportWarning::TooManySignatures);
            }
        } else {
            report
                .warnings
                .push(ReportWarning::UnknownEntry { entry: entry_index });
        }

        // `dwLength` counts the header and data; the next entry starts on
        // the next 8-byte boundary, and the padding must be zero.
        let end = pos.saturating_add(ENTRY_HEADER).saturating_add(body.len());
        let next = end
            .checked_add(ENTRY_ALIGNMENT - 1)
            .map_or(table.len(), |v| v & !(ENTRY_ALIGNMENT - 1))
            .min(table.len());
        if table
            .get(end..next)
            .is_some_and(|pad| pad.iter().any(|b| *b != 0))
        {
            report.warnings.push(ReportWarning::UnexpectedTableData {
                offset: file_offset(table_offset, end),
            });
        }
        pos = next;
    }
    malformed
}

/// Parses and verifies one signature and, recursively, its nested ones.
struct Walker<'r> {
    image: &'r AuthenticodeHashes,
    options: &'r VerifyOptions,
    report: &'r mut SignatureReport,
    entry: usize,
}

impl Walker<'_> {
    fn signature(
        &mut self,
        der: &[u8],
        base: usize,
        kind: SignatureKind,
        parent: Option<usize>,
        depth: u8,
    ) {
        let index = self.report.signatures.len();
        let (mut info, nested) = match pkcs7::parse_content_info(der, base) {
            Ok((signed, trailing)) => {
                let mut info = check(&signed, self.image, self.options);
                // Signers pad entries with up to 7 zero bytes; more, or
                // anything non-zero, is unsigned data hidden in the file.
                let all_zero = trailing.iter().all(|b| *b == 0);
                if !trailing.is_empty() && (trailing.len() >= ENTRY_ALIGNMENT || !all_zero) {
                    let mut warnings = Warnings(std::mem::take(&mut info.warnings));
                    warnings.push(SignatureWarning::TrailingData {
                        len: trailing.len(),
                        all_zero,
                    });
                    info.warnings = warnings.0;
                }
                (info, signed.signer.nested)
            }
            Err(e) => (malformed(e), Vec::new()),
        };
        info.index = index;
        info.kind = kind;
        info.entry = self.entry;
        info.parent = parent;
        info.depth = depth;
        if info.untrusted_signer_attrs {
            self.report
                .warnings
                .push(ReportWarning::DigestMismatchTolerated { signature: index });
        }
        self.report.signatures.push(info);

        for (child, offset) in nested {
            let warning = if depth >= MAX_NESTING_DEPTH {
                Some(SignatureWarning::NestingTooDeep)
            } else if self.report.signatures.len() >= MAX_SIGNATURES {
                if !self
                    .report
                    .warnings
                    .contains(&ReportWarning::TooManySignatures)
                {
                    self.report.warnings.push(ReportWarning::TooManySignatures);
                }
                Some(SignatureWarning::LimitReached)
            } else {
                None
            };
            match warning {
                Some(w) => {
                    if let Some(me) = self.report.signatures.get_mut(index) {
                        let mut warnings = Warnings(std::mem::take(&mut me.warnings));
                        warnings.push(w);
                        me.warnings = warnings.0;
                    }
                }
                None => {
                    self.signature(child, offset, SignatureKind::Nested, Some(index), depth + 1)
                }
            }
        }
    }
}

/// A placeholder [`SignatureInfo`]; the walker fills in the position fields.
pub(crate) fn blank(status: SignatureStatus) -> SignatureInfo {
    SignatureInfo {
        index: 0,
        total: 0,
        kind: SignatureKind::Embedded,
        entry: 0,
        parent: None,
        depth: 0,
        digest_alg: None,
        signed_image_digest: None,
        signer_digest_alg: None,
        sig_alg: None,
        key_alg: None,
        key_bits: None,
        digest_match: None,
        signature_valid: SignatureCheck::NotChecked,
        status,
        signer: None,
        untrusted_signer_attrs: false,
        signer_id: None,
        certs_in_blob: Vec::new(),
        pe_image_flags: None,
        page_hashes: None,
        timestamp_tokens: Vec::new(),
        signature_value: Vec::new(),
        os_ci_issues: vec![OsCiIssue::SignerUnknown],
        warnings: Vec::new(),
    }
}

fn malformed(e: super::signature::SignatureError) -> SignatureInfo {
    blank(SignatureStatus::Malformed(e))
}

/// Runs every check on one parsed signature.
pub(crate) fn check(
    sd: &SignedData<'_>,
    image: &AuthenticodeHashes,
    options: &VerifyOptions,
) -> SignatureInfo {
    let mut warnings = Warnings(sd.warnings.0.clone());
    let signer = &sd.signer;
    let indirect = &sd.indirect;

    let signer_cert = find_signer_cert(&sd.certificates, &signer.sid, &mut warnings);

    let image_alg = indirect.digest_alg.as_ref().ok().copied();
    let signer_alg = signer.digest_alg.as_ref().ok().copied();
    if !sd.signer_digest_listed {
        warnings.push(SignatureWarning::SignerDigestNotListed);
    }
    if image_alg == Some(DigestAlgorithm::Sha1) || signer_alg == Some(DigestAlgorithm::Sha1) {
        warnings.push(SignatureWarning::Sha1Digest);
    }
    if image_alg.is_some() && signer_alg.is_some() && image_alg != signer_alg {
        warnings.push(SignatureWarning::DigestAlgorithmsDiffer);
    }

    let signature_valid = check_signature(
        signer,
        indirect.content,
        signer_cert.as_ref().map(|(_, c)| c),
    );

    // Compare the signed image digest with the file.
    let digest_match = match indirect.digest_alg {
        Ok(alg) => alg
            .hash_algorithm()
            .and_then(|h| image.get(h))
            .map(|d| d.as_bytes() == indirect.digest),
        Err(_) => None,
    };

    let weak = [image_alg, signer_alg]
        .into_iter()
        .flatten()
        .find(|a| a.is_broken());
    let status = if let Some(alg) = weak {
        SignatureStatus::WeakAlgorithm(alg)
    } else {
        match (&signature_valid, digest_match) {
            (SignatureCheck::Invalid(why), _) => SignatureStatus::BadSignature(*why),
            (SignatureCheck::Unsupported(why), _) => SignatureStatus::Unsupported(why.clone()),
            // `check_signature` never returns this; fail closed if it does.
            (SignatureCheck::NotChecked, _) => {
                SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
            }
            (SignatureCheck::Valid, Some(true)) if !image.status.is_conformant() => {
                SignatureStatus::NonConformantImage
            }
            (SignatureCheck::Valid, Some(true)) => SignatureStatus::Valid,
            (SignatureCheck::Valid, Some(false)) => SignatureStatus::DigestMismatch,
            (SignatureCheck::Valid, None) => {
                SignatureStatus::Unsupported(match &indirect.digest_alg {
                    Ok(alg) => Unsupported::ImageDigestUnavailable(*alg),
                    Err(oid) => Unsupported::UnknownDigest(oid.clone()),
                })
            }
        }
    };

    let (key_alg, key_bits) = match &signer_cert {
        Some((_, cert)) => (Some(cert.key_alg.clone()), cert.key_bits),
        None => (None, None),
    };
    let os_ci_issues = os_ci_issues(key_alg.as_ref(), key_bits, weak);
    if let (Some(KeyAlgorithm::Rsa), Some(bits)) = (&key_alg, key_bits) {
        if bits < 2048 {
            warnings.push(SignatureWarning::SmallRsaKey(bits));
        }
    }

    let tolerated = options.tolerate_digest_mismatch && status == SignatureStatus::DigestMismatch;
    let signer_attrs = match (&status, &signer_cert) {
        (SignatureStatus::Valid, Some((i, _))) => Some(*i),
        (SignatureStatus::DigestMismatch, Some((i, _))) if tolerated => Some(*i),
        _ => None,
    }
    .map(|signer_cert| SignerAttributes {
        program_name: signer.opus.program_name.clone(),
        more_info_url: signer.opus.more_info_url.clone(),
        statement_type: signer.statement_type,
        signing_time: signer.signing_time,
        signer_cert,
        signed_metadata: signer.signed_metadata.clone(),
    });

    SignatureInfo {
        digest_alg: image_alg,
        signed_image_digest: Some(indirect.digest.to_vec()),
        signer_digest_alg: signer_alg,
        sig_alg: Some(signer.sig_alg.clone()),
        key_alg,
        key_bits,
        digest_match,
        signature_valid,
        status,
        untrusted_signer_attrs: tolerated && signer_attrs.is_some(),
        signer: signer_attrs,
        signer_id: Some(signer.sid.clone()),
        certs_in_blob: sd.certificates.iter().map(|c| c.to_vec()).collect(),
        pe_image_flags: indirect.pe_image_flags,
        page_hashes: indirect.page_hashes.clone(),
        timestamp_tokens: signer.timestamps.clone(),
        signature_value: signer.signature.to_vec(),
        os_ci_issues,
        warnings: warnings.0,
        ..blank(SignatureStatus::Valid)
    }
}

/// The certificate among `certificates` that `sid` names, with its index.
/// Records a warning for every certificate that does not parse, and for a
/// second match (the first is used).
pub(crate) fn find_signer_cert<'a>(
    certificates: &[&'a [u8]],
    sid: &SignerIdentifier,
    warnings: &mut Warnings,
) -> Option<(usize, Certificate<'a>)> {
    let mut signer_cert: Option<(usize, Certificate<'a>)> = None;
    for (i, der) in certificates.iter().enumerate() {
        match pkcs7::parse_certificate(der) {
            Ok(cert) if pkcs7::matches(&cert, sid) => {
                if signer_cert.is_some() {
                    warnings.push(SignatureWarning::AmbiguousSignerCertificate);
                } else {
                    signer_cert = Some((i, cert));
                }
            }
            Ok(_) => {}
            Err(_) => warnings.push(SignatureWarning::UnparseableCertificate(i)),
        }
    }
    signer_cert
}

/// The `messageDigest` attribute check against `content` (the content
/// octets of the signed content), then the signature itself.
pub(crate) fn check_signature(
    signer: &Signer<'_>,
    content: &[u8],
    cert: Option<&Certificate<'_>>,
) -> SignatureCheck {
    let signer_alg = match &signer.digest_alg {
        Ok(alg) => *alg,
        Err(oid) => return SignatureCheck::Unsupported(Unsupported::UnknownDigest(oid.clone())),
    };
    let Some(hash_alg) = signer_alg.hash_algorithm() else {
        return SignatureCheck::Unsupported(Unsupported::WeakAlgorithm(signer_alg));
    };
    let content_digest = hash_bytes(content, AlgorithmSet::from(hash_alg));
    let matches = content_digest
        .get(hash_alg)
        .is_some_and(|d| d.as_bytes() == signer.message_digest);
    if !matches {
        return SignatureCheck::Invalid(BadSignature::MessageDigestMismatch);
    }
    let Some(cert) = cert else {
        return SignatureCheck::Invalid(BadSignature::SignerCertificateNotFound);
    };
    let scheme = match scheme(&signer.sig_alg, signer_alg) {
        Ok(scheme) => scheme,
        Err(why) => return SignatureCheck::Unsupported(why),
    };
    let key = match cert.key {
        Some(CertKey::Rsa { der, bits }) => PublicKey::Rsa { der, bits },
        Some(CertKey::Ec { curve, point }) => PublicKey::Ec { curve, point },
        None => {
            return SignatureCheck::Unsupported(Unsupported::KeyAlgorithm(cert.key_alg.clone()));
        }
    };
    match crypto::verify(scheme, key, &signer.signed_attrs, signer.signature) {
        Verified::Valid => SignatureCheck::Valid,
        Verified::Invalid => SignatureCheck::Invalid(BadSignature::SignatureInvalid),
        Verified::Unsupported(why) => SignatureCheck::Unsupported(why),
    }
}

/// The scheme to verify with. The digest a scheme uses is always the
/// SignerInfo's (parsing rejects a conflicting one).
pub(crate) fn scheme(
    alg: &SignatureAlgorithm,
    signer_alg: DigestAlgorithm,
) -> Result<Scheme, Unsupported> {
    match alg {
        SignatureAlgorithm::RsaPkcs1(d) => Ok(Scheme::RsaPkcs1(*d)),
        SignatureAlgorithm::Ecdsa(d) => Ok(Scheme::Ecdsa(*d)),
        SignatureAlgorithm::RsaPss {
            digest,
            mgf1_digest,
            salt_len,
        } => {
            let salt_matches = usize::try_from(*salt_len).is_ok_and(|s| s == digest.digest_len());
            if *digest == signer_alg && mgf1_digest == digest && salt_matches {
                Ok(Scheme::RsaPss(*digest))
            } else {
                Err(Unsupported::PssParameters)
            }
        }
        other => Err(Unsupported::SignatureAlgorithm(other.clone())),
    }
}

pub(crate) fn os_ci_issues(
    key_alg: Option<&KeyAlgorithm>,
    key_bits: Option<u32>,
    weak: Option<DigestAlgorithm>,
) -> Vec<OsCiIssue> {
    let mut issues = Vec::new();
    match (key_alg, key_bits) {
        (None, _) => issues.push(OsCiIssue::SignerUnknown),
        (Some(KeyAlgorithm::Rsa), Some(bits)) if bits > 4096 => {
            issues.push(OsCiIssue::RsaKeyTooLarge(bits))
        }
        (Some(KeyAlgorithm::Rsa), _) => {}
        (Some(other), _) => issues.push(OsCiIssue::NotRsa(other.clone())),
    }
    if let Some(alg) = weak {
        issues.push(OsCiIssue::WeakDigest(alg));
    }
    issues
}

/// The rank of a signature's weaker digest: SHA-2 above SHA-1.
fn strength(sig: &SignatureInfo) -> u8 {
    let rank = |alg: Option<DigestAlgorithm>| match alg {
        Some(a) if a.is_sha2() => 2,
        Some(DigestAlgorithm::Sha1) => 1,
        _ => 0,
    };
    rank(sig.digest_alg).min(rank(sig.signer_digest_alg))
}

/// The first valid signature with the strongest digest.
pub(crate) fn select_primary(signatures: &[SignatureInfo]) -> Option<usize> {
    let mut best: Option<(usize, u8)> = None;
    for sig in signatures.iter().filter(|s| s.status.is_valid()) {
        let s = strength(sig);
        if best.is_none_or(|(_, b)| s > b) {
            best = Some((sig.index, s));
        }
    }
    best.map(|(i, _)| i)
}
