//! Script signature blocks and signed metadata (#52).
//!
//! Two kinds of fixture:
//!
//! - `fixtures/script`: scripts written and signed by `generate.sh` there,
//!   with jsign (an independent signer whose script digests agree with OS
//!   tooling) and a throwaway test CA, in every format, encoding and
//!   line-ending combination. Each must verify, and fail with a digest
//!   mismatch when one character changes.
//! - Scripts signed here, by [`Signer`]: a P-256 key generated per run,
//!   a certificate and SignedData built byte by byte. These cover the
//!   cases no signer makes on request: signed metadata attributes, broken
//!   blocks, mismatched packages, nested signatures, and trust policy.
//!
//! The digest rules themselves were checked against scripts signed by OS
//! tooling and against signed scripts the OS ships; `sip_digest` below is a
//! second, independent implementation of them that the library must agree
//! with on every fixture.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::path::Path;

use palisade_fileid::authenticode::{
    DigestAlgorithm, SignatureError, SignatureKind, SignatureStatus, SignatureWarning,
    SignedMetadata, SigningState, TrustConfig, UntrustedReason,
};
use palisade_fileid::script::{
    BlockError, DEFAULT_MAX_SCRIPT_SIZE, ScriptAnchorPolicy, ScriptAnchorSource,
    ScriptInvalidReason, ScriptKind, ScriptOptions, ScriptReport, ScriptSigningState,
    ScriptTrustAnchors, ScriptWarning, TextEncoding, TextIssue, evaluate_script_trust,
    verify_script, verify_script_file,
};
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest as _, Sha256};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/script");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn kind_of(name: &str) -> ScriptKind {
    ScriptKind::from_path(Path::new(name)).unwrap()
}

fn verify(data: &[u8], kind: ScriptKind) -> ScriptReport {
    verify_script(data, kind, &ScriptOptions::default())
}

/// Every signed fixture `generate.sh` writes.
fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(FIXTURES)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| ScriptKind::from_path(Path::new(n)).is_some())
        .filter(|n| !n.contains("nonascii"))
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// An independent implementation of the digest, for differential checks.

const STYLES: &[(&str, &str, &str)] = &[
    // (extensions, begin line, end line)
    (
        "ps1 psm1 psd1",
        "# SIG # Begin signature block",
        "# SIG # End signature block",
    ),
    (
        "ps1xml psc1 cdxml",
        "<!-- SIG # Begin signature block -->",
        "<!-- SIG # End signature block -->",
    ),
    (
        "mof",
        "/* SIG # Begin signature block */",
        "/* SIG # End signature block */",
    ),
    (
        "vbs",
        "'' SIG '' Begin signature block",
        "'' SIG '' End signature block",
    ),
    (
        "js",
        "// SIG // Begin signature block",
        "// SIG // End signature block",
    ),
    ("wsf", "<signature>", "</signature>"),
];

fn markers(ext: &str) -> (&'static str, &'static str) {
    let (_, b, e) = STYLES
        .iter()
        .find(|(exts, _, _)| exts.split(' ').any(|x| x == ext))
        .unwrap();
    (b, e)
}

/// Decodes `data` by its byte order mark into UTF-16 units, and whether it
/// had one.
fn utf16_of(data: &[u8]) -> (Vec<u16>, bool) {
    match data {
        [0xff, 0xfe, rest @ ..] => (
            rest.chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect(),
            true,
        ),
        [0xfe, 0xff, rest @ ..] => (
            rest.chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect(),
            true,
        ),
        [0xef, 0xbb, 0xbf, rest @ ..] => (
            std::str::from_utf8(rest).unwrap().encode_utf16().collect(),
            true,
        ),
        _ => (
            std::str::from_utf8(data).unwrap().encode_utf16().collect(),
            false,
        ),
    }
}

/// The SHA-256 a script's package signs, computed from scratch: UTF-16LE of
/// the text without "CRLF begin ... end CRLF"; the PowerShell package
/// hashes a byte order mark as U+FEFF, the script host packages append the
/// block's position.
fn sip_digest(data: &[u8], ext: &str) -> [u8; 32] {
    let (units, bom) = utf16_of(data);
    let text = String::from_utf16(&units).unwrap();
    let (begin, end) = markers(ext);
    let start = text.find(&format!("\r\n{begin}\r\n")).unwrap();
    let stop = text.find(&format!("{end}\r\n")).unwrap() + end.len() + 2;
    let before: Vec<u16> = text[..start].encode_utf16().collect();
    let after: Vec<u16> = text[stop..].encode_utf16().collect();
    let powershell = matches!(
        ext,
        "ps1" | "psm1" | "psd1" | "ps1xml" | "psc1" | "cdxml" | "mof"
    );
    let mut h = Sha256::new();
    if powershell && bom {
        h.update([0xff, 0xfe]);
    }
    for u in before.iter().chain(&after) {
        h.update(u.to_le_bytes());
    }
    if !powershell {
        h.update((before.len() as u32).to_le_bytes());
    }
    h.finalize().into()
}

/// The digest a signature signs: the last OCTET STRING of the
/// `SpcIndirectDataContent`, found by its DigestInfo prefix.
fn signed_digest(report: &ScriptReport) -> Vec<u8> {
    report
        .signature()
        .and_then(|s| s.signed_image_digest.clone())
        .unwrap()
}

// ---------------------------------------------------------------------------
// The committed fixture matrix.

#[test]
fn every_fixture_verifies() {
    let names = fixture_names();
    // 5 formats x 3 encodings x 3 line endings, 3 formats in UTF-16BE x 3,
    // and the two other PowerShell extensions.
    assert_eq!(names.len(), 45 + 9 + 2, "{names:?}");
    for name in &names {
        let data = fixture(name);
        let report = verify(&data, kind_of(name));
        assert_eq!(
            report.signing_state,
            ScriptSigningState::Valid,
            "{name}: {report:#?}"
        );
        let sig = report.signature().unwrap();
        assert_eq!(sig.kind, SignatureKind::Script);
        assert_eq!(sig.status, SignatureStatus::Valid);
        assert_eq!(sig.digest_match, Some(true));
        assert_eq!(report.signatures.primary, Some(0));
        assert_eq!(report.signatures.signing_state, SigningState::Valid);
        assert!(report.text_issue.is_none());
        assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);
        // The independent digest agrees with the library and the signer.
        let ext = name.rsplit('.').next().unwrap();
        let expected = sip_digest(&data, ext);
        assert_eq!(signed_digest(&report), expected, "{name}");
        let sha256 = report
            .sip_digests
            .as_ref()
            .and_then(|d| d.get(palisade_fileid::hash::HashAlgorithm::Sha256))
            .unwrap();
        assert_eq!(sha256.as_bytes(), expected, "{name}");
    }
}

#[test]
fn fixtures_cover_every_encoding() {
    for (name, encoding) in [
        ("ps1-utf8-crlf.ps1", TextEncoding::NoBom),
        ("ps1-utf8bom-lf.ps1", TextEncoding::Utf8Bom),
        ("ps1-utf16le-cr.ps1", TextEncoding::Utf16Le),
        ("vbs-utf16be-crlf.vbs", TextEncoding::Utf16Be),
        ("wsf-utf16be-lf.wsf", TextEncoding::Utf16Be),
    ] {
        assert_eq!(
            verify(&fixture(name), kind_of(name)).encoding,
            Some(encoding),
            "{name}"
        );
    }
}

/// Changes one character of the script text, keeping its encoding valid:
/// the first ASCII letter `x` of "fixture" becomes `y`.
fn tamper(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let at = data.windows(1).position(|w| w == b"x").unwrap();
    out[at] = b'y';
    out
}

#[test]
fn changing_one_character_is_a_digest_mismatch() {
    for name in fixture_names() {
        let data = tamper(&fixture(&name));
        let report = verify(&data, kind_of(&name));
        assert_eq!(
            report.signing_state,
            ScriptSigningState::DigestMismatch,
            "{name}: {report:#?}"
        );
        let sig = report.signature().unwrap();
        assert_eq!(sig.status, SignatureStatus::DigestMismatch);
        assert_eq!(sig.digest_match, Some(false));
        assert!(sig.signer.is_none());
        assert_eq!(report.signatures.primary, None);
    }
}

#[test]
fn changing_line_endings_is_a_digest_mismatch() {
    // An LF script converted to CRLF (as a checkout might) is a different
    // text: its digest differs, so it is not validly signed.
    let data = fixture("ps1-utf8-lf.ps1");
    let begin = find(&data, b"\r\n# SIG # Begin");
    let mut converted = Vec::new();
    for b in &data[..begin] {
        if *b == b'\n' {
            converted.push(b'\r');
        }
        converted.push(*b);
    }
    converted.extend_from_slice(&data[begin..]);
    let report = verify(&converted, ScriptKind::PowerShell);
    assert_eq!(report.signing_state, ScriptSigningState::DigestMismatch);
    // The normalised hash does not change.
    assert_eq!(
        report.normalised_hash,
        verify(&data, ScriptKind::PowerShell).normalised_hash
    );
}

#[test]
fn line_ending_variants_have_distinct_digests() {
    for stem in ["ps1-utf8bom", "vbs-utf16le", "wsf-utf8"] {
        let ext = stem.split('-').next().unwrap();
        let digests: Vec<_> = ["crlf", "lf", "cr"]
            .iter()
            .map(|eol| {
                let name = format!("{stem}-{eol}.{ext}");
                verify(&fixture(&name), kind_of(&name)).sip_digests
            })
            .collect();
        assert_ne!(digests[0], digests[1], "{stem}");
        assert_ne!(digests[1], digests[2], "{stem}");
        assert_ne!(digests[0], digests[2], "{stem}");
    }
}

#[test]
fn normalised_hash_ignores_encoding_line_endings_and_signature() {
    // The same text in every encoding and line ending, signed: one
    // normalised hash per format (for the text with a byte order mark,
    // which carries the same characters in each encoding).
    for ext in ["ps1", "vbs", "js", "wsf", "ps1xml"] {
        let mut hashes = Vec::new();
        for encoding in ["utf8bom", "utf16le"] {
            for eol in ["crlf", "lf", "cr"] {
                let name = format!("{ext}-{encoding}-{eol}.{ext}");
                hashes.push(verify(&fixture(&name), kind_of(&name)).normalised_hash);
            }
        }
        assert!(hashes[0].is_some(), "{ext}");
        assert!(hashes.iter().all(|h| *h == hashes[0]), "{ext}: {hashes:?}");
    }
    // It is the SHA-256 of the UTF-8 text with LF line endings.
    let report = verify(&fixture("ps1-utf16le-crlf.ps1"), ScriptKind::PowerShell);
    let expected: [u8; 32] = Sha256::digest(
        "# palisade fixture caf\u{e9} \u{20ac} \u{1f600}\nWrite-Output \"palisade fixture caf\u{e9} \u{20ac} \u{1f600}\"\n",
    )
    .into();
    assert_eq!(report.normalised_hash.unwrap().as_bytes(), expected);
}

#[test]
fn stripping_the_block_gives_the_unsigned_digest() {
    // A PowerShell script's package digest is the same signed and unsigned.
    for name in ["ps1-utf8bom-crlf.ps1", "ps1-utf16le-lf.ps1"] {
        let data = fixture(name);
        let signed = verify(&data, ScriptKind::PowerShell);
        let start = block_start(&data);
        let unsigned = verify(&data[..start], ScriptKind::PowerShell);
        assert_eq!(unsigned.signing_state, ScriptSigningState::Unsigned);
        assert_eq!(unsigned.sip_digests, signed.sip_digests, "{name}");
        assert_eq!(unsigned.normalised_hash, signed.normalised_hash, "{name}");
        assert_eq!(
            unsigned.catalog_digests().flat_sha256,
            signed.catalog_digests().flat_sha256
        );
    }
}

#[test]
fn block_location_is_reported() {
    let data = fixture("vbs-utf16le-crlf.vbs");
    let report = verify(&data, ScriptKind::VbScript);
    let block = report.block.unwrap();
    assert_eq!(block.offset as usize, block_start(&data));
    assert_eq!((block.offset + block.len) as usize, data.len());
}

/// The byte offset of the CRLF before the begin line.
fn block_start(data: &[u8]) -> usize {
    let (units, bom) = utf16_of(data);
    let _ = (units, bom);
    for needle in [
        &b"\r\n# SIG # Begin"[..],
        b"\r\n'' SIG '' Begin",
        b"\r\n// SIG // Begin",
        b"\r\n<!-- SIG # Begin",
        b"\r\n<signature>",
    ] {
        if let Some(at) = data.windows(needle.len()).position(|w| w == needle) {
            return at;
        }
        let wide: Vec<u8> = needle.iter().flat_map(|b| [*b, 0]).collect();
        if let Some(at) = data.windows(wide.len()).position(|w| w == wide) {
            return at;
        }
    }
    panic!("no block");
}

fn find(data: &[u8], needle: &[u8]) -> usize {
    data.windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

#[test]
fn non_ascii_without_a_byte_order_mark_is_never_valid() {
    // These are signed, but their digest depends on the code page of the
    // machine that reads them.
    for name in ["ps1-nobom-nonascii.ps1", "vbs-nobom-nonascii.vbs"] {
        let report = verify(&fixture(name), kind_of(name));
        assert_eq!(
            report.signing_state,
            ScriptSigningState::Invalid(ScriptInvalidReason::Text(TextIssue::NonAsciiWithoutBom)),
            "{name}"
        );
        assert_eq!(report.text_issue, Some(TextIssue::NonAsciiWithoutBom));
        assert!(report.signatures.signatures.is_empty());
        assert!(report.sip_digests.is_none());
        assert!(report.normalised_hash.is_none());
    }
}

#[test]
fn wsf_signature_moved_out_of_place_fails() {
    // Moving the block earlier changes the position the digest covers.
    let data = fixture("wsf-utf8-crlf.wsf");
    let text = std::str::from_utf8(&data).unwrap();
    let start = text.find("\r\n<signature>").unwrap();
    let stop = text.find("</signature>\r\n").unwrap() + "</signature>\r\n".len();
    let block = &text[start..stop];
    let rest = format!("{}{}", &text[..start], &text[stop..]);
    let first_line = rest.find("\r\n").unwrap();
    let moved = format!("{}{}{}", &rest[..first_line], block, &rest[first_line..]);
    let report = verify(moved.as_bytes(), ScriptKind::WindowsScriptFile);
    assert_eq!(report.signing_state, ScriptSigningState::DigestMismatch);
}

#[test]
fn fixture_signature_read_as_another_format_fails() {
    // A VBScript block renamed .js has no JScript block: unsigned. The same
    // signature under JScript markers names the wrong package.
    let data = fixture("vbs-utf8-crlf.vbs");
    assert_eq!(
        verify(&data, ScriptKind::JScript).signing_state,
        ScriptSigningState::Unsigned
    );
    let text = std::str::from_utf8(&data)
        .unwrap()
        .replace("'' SIG '' ", "// SIG // ");
    let report = verify(text.as_bytes(), ScriptKind::JScript);
    assert_eq!(
        report.signing_state,
        ScriptSigningState::Invalid(ScriptInvalidReason::Signature(SignatureStatus::Malformed(
            SignatureError::SipMismatch
        )))
    );
}

// ---------------------------------------------------------------------------
// A signer for the cases no tool makes on request.

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn int(n: u32) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut content = bytes[skip..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut stack = vec![(*arc & 0x7f) as u8];
        let mut v = *arc >> 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        content.extend(stack.iter().rev());
    }
    tlv(0x06, &content)
}

fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

fn name(cn: &str) -> Vec<u8> {
    seq(&[&set(&[&seq(&[&oid("2.5.4.3"), &utf8(cn)])])])
}

const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

fn alg(o: &str) -> Vec<u8> {
    seq(&[&oid(o)])
}

fn digest_alg() -> Vec<u8> {
    seq(&[&oid(SHA256), &tlv(0x05, &[])])
}

/// The SIP GUIDs, as encoded.
const POWERSHELL_SIP: [u8; 16] = [
    0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51,
];
const VBSCRIPT_SIP: [u8; 16] = [
    0x4e, 0xf0, 0x29, 0x16, 0x99, 0x27, 0xb5, 0x4d, 0x8f, 0xe5, 0xac, 0xe1, 0x0f, 0x17, 0xeb, 0xab,
];

/// A key and a two-certificate chain (root, code-signing leaf), made per
/// run.
struct Signer {
    rng: SystemRandom,
    root_key: EcdsaKeyPair,
    leaf_key: EcdsaKeyPair,
    root: Vec<u8>,
    leaf: Vec<u8>,
}

fn spki(key: &EcdsaKeyPair) -> Vec<u8> {
    seq(&[
        &seq(&[&oid("1.2.840.10045.2.1"), &oid("1.2.840.10045.3.1.7")]),
        &tlv(0x03, &[&[0][..], key.public_key().as_ref()].concat()),
    ])
}

fn ski(key: &EcdsaKeyPair) -> Vec<u8> {
    Sha256::digest(key.public_key().as_ref())[..20].to_vec()
}

impl Signer {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let key = |rng: &SystemRandom| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rng).unwrap();
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), rng).unwrap()
        };
        let root_key = key(&rng);
        let leaf_key = key(&rng);
        let mut s = Self {
            rng,
            root_key,
            leaf_key,
            root: Vec::new(),
            leaf: Vec::new(),
        };
        let validity = seq(&[&tlv(0x17, b"200101000000Z"), &tlv(0x18, b"20991231000000Z")]);
        let ext = |id: &str, critical: bool, value: &[u8]| {
            let crit = if critical {
                tlv(0x01, &[0xff])
            } else {
                Vec::new()
            };
            seq(&[&oid(id), &crit, &tlv(0x04, value)])
        };
        let root_name = name("Palisade Script Test Root");
        let root_tbs = seq(&[
            &tlv(0xa0, &int(2)),
            &int(1),
            &alg(ECDSA_SHA256),
            &root_name,
            &validity,
            &root_name,
            &spki(&s.root_key),
            &tlv(
                0xa3,
                &seq(&[
                    &ext("2.5.29.19", true, &seq(&[&tlv(0x01, &[0xff])])),
                    &ext("2.5.29.15", true, &tlv(0x03, &[0x01, 0x06])),
                    &ext("2.5.29.14", false, &tlv(0x04, &ski(&s.root_key))),
                ]),
            ),
        ]);
        s.root = s.certificate(&root_tbs, true);
        let leaf_tbs = seq(&[
            &tlv(0xa0, &int(2)),
            &int(2),
            &alg(ECDSA_SHA256),
            &root_name,
            &validity,
            &name("Palisade Script Test Signer"),
            &spki(&s.leaf_key),
            &tlv(
                0xa3,
                &seq(&[
                    &ext("2.5.29.15", true, &tlv(0x03, &[0x07, 0x80])),
                    &ext("2.5.29.37", false, &seq(&[&oid("1.3.6.1.5.5.7.3.3")])),
                    &ext("2.5.29.14", false, &tlv(0x04, &ski(&s.leaf_key))),
                    &ext("2.5.29.35", false, &seq(&[&tlv(0x80, &ski(&s.root_key))])),
                ]),
            ),
        ]);
        s.leaf = s.certificate(&leaf_tbs, true);
        s
    }

    fn certificate(&self, tbs: &[u8], by_root: bool) -> Vec<u8> {
        let key = if by_root {
            &self.root_key
        } else {
            &self.leaf_key
        };
        let sig = key.sign(&self.rng, tbs).unwrap();
        seq(&[
            tbs,
            &alg(ECDSA_SHA256),
            &tlv(0x03, &[&[0][..], sig.as_ref()].concat()),
        ])
    }

    fn trust(&self) -> TrustConfig {
        let mut config = TrustConfig::new();
        config.add_anchor("script test root", &self.root).unwrap();
        config
    }

    /// A SignedData over `digest` with SIP `guid`/`version` and the extra
    /// authenticated attributes `extra`; `nested` goes in the
    /// unauthenticated attributes as nested signatures.
    fn signed_data(
        &self,
        digest: &[u8],
        guid: [u8; 16],
        version: u32,
        extra: &[Vec<u8>],
        nested: Option<&[u8]>,
    ) -> Vec<u8> {
        let sip_info = seq(&[
            &int(version),
            &tlv(0x04, &guid),
            &int(0),
            &int(0),
            &int(0),
            &int(0),
            &int(0),
        ]);
        let indirect = seq(&[
            &seq(&[&oid("1.3.6.1.4.1.311.2.1.30"), &sip_info]),
            &seq(&[&digest_alg(), &tlv(0x04, digest)]),
        ]);
        let indirect_content = &indirect[header_len(&indirect)..];
        let message_digest = Sha256::digest(indirect_content);
        let mut attrs = vec![
            seq(&[
                &oid("1.2.840.113549.1.9.3"),
                &set(&[&oid("1.3.6.1.4.1.311.2.1.4")]),
            ]),
            seq(&[
                &oid("1.2.840.113549.1.9.4"),
                &set(&[&tlv(0x04, &message_digest)]),
            ]),
        ];
        attrs.extend(extra.iter().cloned());
        // DER orders SET OF by encoding.
        attrs.sort();
        let attrs_set = set(&attrs.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let sig = self.leaf_key.sign(&self.rng, &attrs_set).unwrap();
        let mut signed_attrs = attrs_set.clone();
        signed_attrs[0] = 0xa0;
        let unsigned = nested
            .map(|n| tlv(0xa1, &seq(&[&oid("1.3.6.1.4.1.311.2.4.1"), &set(&[n])])))
            .unwrap_or_default();
        let signer_info = seq(&[
            &int(1),
            &seq(&[&name("Palisade Script Test Root"), &int(2)]),
            &digest_alg(),
            &signed_attrs,
            &alg(ECDSA_SHA256),
            &tlv(0x04, sig.as_ref()),
            &unsigned,
        ]);
        let sd = seq(&[
            &int(1),
            &set(&[&digest_alg()]),
            &seq(&[&oid("1.3.6.1.4.1.311.2.1.4"), &tlv(0xa0, &indirect)]),
            &tlv(0xa0, &[self.leaf.as_slice(), &self.root].concat()),
            &set(&[&signer_info]),
        ]);
        seq(&[&oid("1.2.840.113549.1.7.2"), &tlv(0xa0, &sd)])
    }
}

fn header_len(der: &[u8]) -> usize {
    if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    }
}

fn metadata_attr(arc: u8, value: &[u8]) -> Vec<u8> {
    seq(&[&oid(&format!("1.3.6.1.4.1.311.2.7.{arc}")), &set(&[value])])
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A block in PowerShell style (or `begin`/`end`/`prefix`/`suffix`) around
/// `der`, as signers write it.
fn block(der: &[u8], begin: &str, end: &str, prefix: &str, suffix: &str) -> String {
    let b64 = base64(der);
    let mut out = format!("\r\n{begin}\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(prefix);
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push_str(suffix);
        out.push_str("\r\n");
    }
    out.push_str(end);
    out.push_str("\r\n");
    out
}

const PS_BEGIN: &str = "# SIG # Begin signature block";
const PS_END: &str = "# SIG # End signature block";

fn ps_block(der: &[u8]) -> String {
    block(der, PS_BEGIN, PS_END, "# ", "")
}

/// Signs the UTF-8 (with BOM) PowerShell script `body`, with `extra`
/// authenticated attributes.
fn sign_ps1(signer: &Signer, body: &str, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut data = b"\xef\xbb\xbf".to_vec();
    data.extend_from_slice(body.as_bytes());
    let mut probe = data.clone();
    probe.extend_from_slice(ps_block(&[0]).as_bytes());
    let digest = sip_digest(&probe, "ps1");
    let der = signer.signed_data(&digest, POWERSHELL_SIP, 0x0001_0000, extra, None);
    data.extend_from_slice(ps_block(&der).as_bytes());
    data
}

const BODY: &str = "Write-Output 'palisade'\r\n";

#[test]
fn signer_here_makes_valid_signatures() {
    let signer = Signer::new();
    let data = sign_ps1(&signer, BODY, &[]);
    let report = verify(&data, ScriptKind::PowerShell);
    assert_eq!(
        report.signing_state,
        ScriptSigningState::Valid,
        "{report:#?}"
    );
    assert!(
        report
            .signature()
            .unwrap()
            .signer
            .as_ref()
            .unwrap()
            .signed_metadata
            .is_empty()
    );
}

#[test]
fn every_signed_metadata_attribute_is_read_back() {
    let signer = Signer::new();
    let values = [
        "Palisade.Deploy",
        "2.1.0",
        "Palisade deployment script",
        "Palisade Tools",
        "2.1",
        "Deploy.ps1",
        "en-AU",
        "Palisade Tests",
        "2026-10-28T12:00:00Z",
        "https://example.invalid/Deploy.ps1",
    ];
    let extra: Vec<Vec<u8>> = values
        .iter()
        .enumerate()
        .map(|(i, v)| metadata_attr(i as u8 + 1, &utf8(v)))
        .collect();
    let data = sign_ps1(&signer, BODY, &extra);
    let report = verify(&data, ScriptKind::PowerShell);
    assert_eq!(
        report.signing_state,
        ScriptSigningState::Valid,
        "{report:#?}"
    );
    let sig = report.signature().unwrap();
    let expected = SignedMetadata {
        internal_name: Some(values[0].into()),
        file_version: Some(values[1].into()),
        file_description: Some(values[2].into()),
        product: Some(values[3].into()),
        product_version: Some(values[4].into()),
        original_filename: Some(values[5].into()),
        language: Some(values[6].into()),
        author: Some(values[7].into()),
        publish_time: Some(values[8].into()),
        source_url: Some(values[9].into()),
    };
    assert_eq!(sig.signer.as_ref().unwrap().signed_metadata, expected);
    assert!(
        !sig.warnings
            .iter()
            .any(|w| matches!(w, SignatureWarning::UnknownAuthenticatedAttribute(_))),
        "{:?}",
        sig.warnings
    );

    // Trusted under the policy anchors: the identity carries them.
    let policy = signer.trust();
    let trust = evaluate_script_trust(
        &report,
        &ScriptTrustAnchors {
            policy: &policy,
            os_root_store: None,
        },
        ScriptAnchorPolicy::Either,
    );
    assert_eq!(trust.anchor, Some(ScriptAnchorSource::PolicyAnchors));
    assert_eq!(trust.signed_metadata, Some(expected));
    assert_eq!(
        trust.publisher_product,
        Some((
            "Palisade Script Test Signer".to_owned(),
            "Palisade Tools".to_owned()
        ))
    );
}

#[test]
fn unreadable_signed_metadata_is_left_out() {
    let signer = Signer::new();
    let extra = vec![
        // Not a UTF8String.
        metadata_attr(1, &tlv(0x1e, &[0, b'x'])),
        // Invalid UTF-8.
        metadata_attr(2, &tlv(0x0c, &[0xff, 0xfe])),
        // A NUL, which a C-string reader would cut at.
        metadata_attr(4, &utf8("Palisade\0Other")),
        // Too long.
        metadata_attr(6, &utf8(&"a".repeat(4097))),
        // Readable.
        metadata_attr(5, &utf8("1.0")),
        // An arc past .10 is an unknown attribute.
        metadata_attr(11, &utf8("x")),
    ];
    let data = sign_ps1(&signer, BODY, &extra);
    let report = verify(&data, ScriptKind::PowerShell);
    assert_eq!(
        report.signing_state,
        ScriptSigningState::Valid,
        "{report:#?}"
    );
    let sig = report.signature().unwrap();
    let meta = &sig.signer.as_ref().unwrap().signed_metadata;
    assert_eq!(
        *meta,
        SignedMetadata {
            product_version: Some("1.0".into()),
            ..SignedMetadata::default()
        }
    );
    let unreadable = sig
        .warnings
        .iter()
        .filter(|w| matches!(w, SignatureWarning::SignedMetadataUnreadable(_)))
        .count();
    assert_eq!(unreadable, 4, "{:?}", sig.warnings);
    assert!(
        sig.warnings
            .iter()
            .any(|w| matches!(w, SignatureWarning::UnknownAuthenticatedAttribute(_)))
    );
}

#[test]
fn duplicate_signed_metadata_is_malformed() {
    let signer = Signer::new();
    let extra = vec![
        metadata_attr(4, &utf8("Palisade Tools")),
        metadata_attr(4, &utf8("Other Tools")),
    ];
    let data = sign_ps1(&signer, BODY, &extra);
    let report = verify(&data, ScriptKind::PowerShell);
    assert!(
        matches!(
            report.signing_state,
            ScriptSigningState::Invalid(ScriptInvalidReason::Signature(
                SignatureStatus::Malformed(SignatureError::DuplicateAttribute(_))
            ))
        ),
        "{report:#?}"
    );
    assert_eq!(report.signatures.primary, None);
    // Two values in one attribute is malformed too.
    let two = seq(&[
        &oid("1.3.6.1.4.1.311.2.7.4"),
        &set(&[&utf8("A"), &utf8("B")]),
    ]);
    let data = sign_ps1(&signer, BODY, &[two]);
    assert!(matches!(
        verify(&data, ScriptKind::PowerShell).signing_state,
        ScriptSigningState::Invalid(ScriptInvalidReason::Signature(SignatureStatus::Malformed(
            SignatureError::AttributeValueCount(_)
        )))
    ));
}

#[test]
fn powershell_xml_and_mof_styles_verify() {
    let signer = Signer::new();
    for (kind, ext, begin, end, prefix, suffix) in [
        (
            ScriptKind::PowerShellXml,
            "ps1xml",
            "<!-- SIG # Begin signature block -->",
            "<!-- SIG # End signature block -->",
            "<!-- ",
            " -->",
        ),
        (
            ScriptKind::Mof,
            "mof",
            "/* SIG # Begin signature block */",
            "/* SIG # End signature block */",
            "/* ",
            " */",
        ),
    ] {
        let body = "<Types></Types>\r\n";
        let mut probe = body.as_bytes().to_vec();
        probe.extend_from_slice(block(&[0], begin, end, prefix, suffix).as_bytes());
        let digest = sip_digest(&probe, ext);
        let der = signer.signed_data(&digest, POWERSHELL_SIP, 0x0001_0000, &[], None);
        let mut data = body.as_bytes().to_vec();
        data.extend_from_slice(block(&der, begin, end, prefix, suffix).as_bytes());
        let report = verify(&data, kind);
        assert_eq!(
            report.signing_state,
            ScriptSigningState::Valid,
            "{ext}: {report:#?}"
        );
    }
}

#[test]
fn wrong_package_is_malformed() {
    let signer = Signer::new();
    let mut probe = BODY.as_bytes().to_vec();
    probe.extend_from_slice(ps_block(&[0]).as_bytes());
    let digest = sip_digest(&probe, "ps1");
    for (guid, version) in [(VBSCRIPT_SIP, 0x0001_0000), (POWERSHELL_SIP, 1)] {
        let der = signer.signed_data(&digest, guid, version, &[], None);
        let mut data = BODY.as_bytes().to_vec();
        data.extend_from_slice(ps_block(&der).as_bytes());
        assert_eq!(
            verify(&data, ScriptKind::PowerShell).signing_state,
            ScriptSigningState::Invalid(ScriptInvalidReason::Signature(
                SignatureStatus::Malformed(SignatureError::SipMismatch)
            ))
        );
    }
}

#[test]
fn nested_signatures_are_ignored_with_a_warning() {
    let signer = Signer::new();
    let mut probe = BODY.as_bytes().to_vec();
    probe.extend_from_slice(ps_block(&[0]).as_bytes());
    let digest = sip_digest(&probe, "ps1");
    // The nested signature signs another digest: it is never verified, so
    // it cannot make the file valid, and an invalid one cannot break it.
    let nested = signer.signed_data(&[0x55; 32], POWERSHELL_SIP, 0x0001_0000, &[], None);
    let der = signer.signed_data(&digest, POWERSHELL_SIP, 0x0001_0000, &[], Some(&nested));
    let mut data = BODY.as_bytes().to_vec();
    data.extend_from_slice(ps_block(&der).as_bytes());
    let report = verify(&data, ScriptKind::PowerShell);
    assert_eq!(report.signing_state, ScriptSigningState::Valid);
    assert_eq!(
        report.warnings,
        vec![ScriptWarning::NestedSignaturesIgnored(1)]
    );
    assert_eq!(report.signatures.signatures.len(), 1);

    // A nested element that is not DER makes the whole signature malformed.
    let mut bad_nested = nested.clone();
    bad_nested[1] = 0x80;
    let der = signer.signed_data(&digest, POWERSHELL_SIP, 0x0001_0000, &[], Some(&bad_nested));
    let mut data = BODY.as_bytes().to_vec();
    data.extend_from_slice(ps_block(&der).as_bytes());
    assert!(matches!(
        verify(&data, ScriptKind::PowerShell).signing_state,
        ScriptSigningState::Invalid(ScriptInvalidReason::Signature(SignatureStatus::Malformed(
            _
        )))
    ));
}

#[test]
fn a_forged_signature_is_not_valid() {
    let signer = Signer::new();
    let mut data = sign_ps1(&signer, BODY, &[]);
    // Flip a bit in the middle of the signature's base64: the block still
    // parses, but the SignedData no longer verifies or no longer decodes.
    let text = String::from_utf8(data.clone()).unwrap();
    let line = text.find("\r\n# M").unwrap() + 4 + 40;
    data[line] = if data[line] == b'A' { b'B' } else { b'A' };
    let report = verify(&data, ScriptKind::PowerShell);
    assert!(
        matches!(report.signing_state, ScriptSigningState::Invalid(_)),
        "{report:#?}"
    );
    assert_eq!(report.signatures.primary, None);
}

// ---------------------------------------------------------------------------
// Malformed blocks: each case is a valid signed script with one change.

fn signed_text() -> (Signer, String) {
    let signer = Signer::new();
    let data = sign_ps1(&signer, BODY, &[]);
    (signer, String::from_utf8(data[3..].to_vec()).unwrap())
}

fn verify_text(text: &str) -> ScriptReport {
    let mut data = b"\xef\xbb\xbf".to_vec();
    data.extend_from_slice(text.as_bytes());
    verify(&data, ScriptKind::PowerShell)
}

fn block_error(text: &str) -> Option<BlockError> {
    match verify_text(text).signing_state {
        ScriptSigningState::Invalid(ScriptInvalidReason::Block(e)) => Some(e),
        _ => None,
    }
}

#[test]
fn malformed_blocks_are_invalid() {
    let (_, good) = signed_text();
    assert_eq!(verify_text(&good).signing_state, ScriptSigningState::Valid);
    let first_data = good.find("\r\n# M").unwrap() + 2;
    let end = good.find(PS_END).unwrap();

    // Truncated: the end line and the last data lines are gone.
    assert_eq!(
        block_error(&good[..first_data + 30]),
        Some(BlockError::MissingEnd)
    );
    // Truncated mid-block, keeping whole lines.
    assert_eq!(block_error(&good[..end]), Some(BlockError::MissingEnd));
    // Two blocks.
    let twice = format!("{good}{}", &good[good.find("\r\n# SIG").unwrap()..]);
    assert_eq!(block_error(&twice), Some(BlockError::MultipleBlocks));
    // Not at the end of the file.
    assert_eq!(
        block_error(&format!("{good}Write-Output 'after'\r\n")),
        Some(BlockError::NotAtEnd)
    );
    // No line break after the end line.
    assert_eq!(
        block_error(good.strip_suffix("\r\n").unwrap()),
        Some(BlockError::Unterminated)
    );
    // An end line with no begin line.
    assert_eq!(
        block_error(&good.replace(PS_BEGIN, "# SIG # Begin signature")),
        Some(BlockError::MissingBegin)
    );
    // A data line that is not base64.
    let bad_char = format!("{}*{}", &good[..first_data + 4], &good[first_data + 5..]);
    assert_eq!(
        block_error(&bad_char),
        Some(BlockError::BadLine { line: 1 })
    );
    // A data line without its prefix.
    let no_prefix = format!("{}{}", &good[..first_data], &good[first_data + 2..]);
    assert_eq!(
        block_error(&no_prefix),
        Some(BlockError::BadLine { line: 1 })
    );
    // A data line ending in a bare LF.
    let nl = good[first_data..].find("\r\n").unwrap() + first_data;
    let bare_lf = format!("{}{}", &good[..nl], &good[nl + 1..]);
    assert_eq!(
        block_error(&bare_lf),
        Some(BlockError::BadLineEnding { line: 1 })
    );
    // A blank line inside the block.
    let blank = format!("{}\r\n{}", &good[..first_data], &good[first_data..]);
    assert_eq!(block_error(&blank), Some(BlockError::BadLine { line: 1 }));
    // The begin line not preceded by CRLF.
    let begin = good.find(PS_BEGIN).unwrap();
    let lf_before = format!("{}\n{}", &good[..begin - 2], &good[begin..]);
    assert_eq!(block_error(&lf_before), Some(BlockError::NoLineBreakBefore));
    let at_start = &good[begin..];
    assert_eq!(block_error(at_start), Some(BlockError::NoLineBreakBefore));
    // An empty block.
    let empty = format!("{}\r\n{PS_BEGIN}\r\n{PS_END}\r\n", &good[..begin - 2]);
    assert_eq!(block_error(&empty), Some(BlockError::Empty));
    // Base64 whose length is not a multiple of four.
    let short = format!("{}{}", &good[..first_data + 2], &good[first_data + 3..]);
    assert_eq!(block_error(&short), Some(BlockError::Base64));
    // Extra bytes after the SignedData.
    let (signer, _) = signed_text();
    let mut probe = BODY.as_bytes().to_vec();
    probe.extend_from_slice(ps_block(&[0]).as_bytes());
    let mut der = signer.signed_data(
        &sip_digest(&probe, "ps1"),
        POWERSHELL_SIP,
        0x0001_0000,
        &[],
        None,
    );
    der.extend_from_slice(&[0, 0, 0]);
    let trailing = format!("{BODY}{}", ps_block(&der));
    let mut data = BODY.as_bytes().to_vec();
    let _ = &mut data;
    assert_eq!(
        match verify(trailing.as_bytes(), ScriptKind::PowerShell).signing_state {
            ScriptSigningState::Invalid(ScriptInvalidReason::Block(e)) => Some(e),
            _ => None,
        },
        Some(BlockError::TrailingData)
    );
}

#[test]
fn marker_variants_are_never_blocks() {
    // Case and spacing variants of the markers are not marker text, so the
    // file is unsigned.
    let (_, good) = signed_text();
    for variant in [
        good.replace(PS_BEGIN, "# sig # Begin signature block")
            .replace(PS_END, "# sig # End signature block"),
        good.replace(PS_BEGIN, "#  SIG # Begin signature block")
            .replace(PS_END, "#  SIG # End signature block"),
    ] {
        let report = verify_text(&variant);
        assert_eq!(
            report.signing_state,
            ScriptSigningState::Unsigned,
            "{variant:?}"
        );
        assert!(report.signatures.signatures.is_empty());
    }
    // The exact marker text anywhere but as a whole block line makes the
    // file invalid: another reader could take it for the block.
    let indented = good
        .replace(PS_BEGIN, &format!(" {PS_BEGIN}"))
        .replace(PS_END, &format!(" {PS_END}"));
    assert_eq!(block_error(&indented), Some(BlockError::NoLineBreakBefore));
    let inline = good.replace(PS_BEGIN, &format!("{PS_BEGIN} extra"));
    assert_eq!(
        block_error(&inline),
        Some(BlockError::BadLineEnding { line: 0 })
    );
    // So does the marker text in the script itself, even inside a string.
    let quoted = format!("Write-Output '{PS_BEGIN}'\r\n{good}");
    assert_eq!(block_error(&quoted), Some(BlockError::MultipleBlocks));
    let quoted_end = format!("Write-Output '{PS_END}'\r\n{good}");
    assert_eq!(block_error(&quoted_end), Some(BlockError::MultipleBlocks));
}

#[test]
fn undecodable_text_with_a_block_is_never_valid() {
    let (_, good) = signed_text();
    let cases: Vec<(Vec<u8>, TextIssue)> = vec![
        // Invalid UTF-8 after a UTF-8 BOM.
        (
            [b"\xef\xbb\xbf\xff".as_slice(), good.as_bytes()].concat(),
            TextIssue::InvalidUtf8,
        ),
        // A NUL without a BOM.
        (
            [b"\0".as_slice(), good.as_bytes()].concat(),
            TextIssue::NulWithoutBom,
        ),
        // Non-ASCII without a BOM.
        (
            [b"\xc3\xa9".as_slice(), good.as_bytes()].concat(),
            TextIssue::NonAsciiWithoutBom,
        ),
        // UTF-16 with an odd length.
        (
            [
                b"\xff\xfe".as_slice(),
                &good
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
                b"\0".as_slice(),
            ]
            .concat(),
            TextIssue::OddUtf16Length,
        ),
        // An unpaired surrogate.
        (
            [
                b"\xff\xfe\x00\xd8".as_slice(),
                &good
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            ]
            .concat(),
            TextIssue::UnpairedSurrogate,
        ),
        // UTF-16BE PowerShell.
        (
            [
                b"\xfe\xff".as_slice(),
                &good
                    .encode_utf16()
                    .flat_map(u16::to_be_bytes)
                    .collect::<Vec<_>>(),
            ]
            .concat(),
            TextIssue::Utf16BeNotSigned,
        ),
    ];
    for (data, issue) in cases {
        let report = verify(&data, ScriptKind::PowerShell);
        assert_eq!(
            report.signing_state,
            ScriptSigningState::Invalid(ScriptInvalidReason::Text(issue)),
            "{issue:?}"
        );
        assert!(report.sip_digests.is_none());
        assert!(report.normalised_hash.is_none());
    }
    // UTF-32LE text has no block a UTF-16 reading can see; it is
    // unsigned, and its text is never hashed.
    let utf32: Vec<u8> = [0xff, 0xfe, 0, 0]
        .into_iter()
        .chain(good.chars().flat_map(|c| u32::from(c).to_le_bytes()))
        .collect();
    let report = verify(&utf32, ScriptKind::PowerShell);
    assert_eq!(report.signing_state, ScriptSigningState::Unsigned);
    assert_eq!(report.text_issue, Some(TextIssue::Utf32Bom));
    assert!(report.sip_digests.is_none());
    // Without a block, undecodable text is unsigned, with no digests.
    let report = verify(b"\xc3\xa9\r\n", ScriptKind::PowerShell);
    assert_eq!(report.signing_state, ScriptSigningState::Unsigned);
    assert_eq!(report.text_issue, Some(TextIssue::NonAsciiWithoutBom));
    assert!(report.sip_digests.is_none());
}

#[test]
fn unsigned_scripts() {
    for kind in [
        ScriptKind::PowerShell,
        ScriptKind::VbScript,
        ScriptKind::JScript,
        ScriptKind::WindowsScriptFile,
    ] {
        let report = verify(b"echo palisade\r\n", kind);
        assert_eq!(report.signing_state, ScriptSigningState::Unsigned);
        assert!(report.signatures.signatures.is_empty());
        assert!(report.normalised_hash.is_some());
        // A .wsf has no block position until it is signed.
        assert_eq!(
            report.sip_digests.is_some(),
            kind != ScriptKind::WindowsScriptFile,
            "{kind:?}"
        );
    }
    let empty = verify(b"", ScriptKind::PowerShell);
    assert_eq!(empty.signing_state, ScriptSigningState::Unsigned);
}

#[test]
fn encoded_scripts_are_unsigned_with_a_warning() {
    // Even with something that looks like a block.
    let data = fixture("vbs-utf8-crlf.vbs");
    for kind in [ScriptKind::EncodedVbScript, ScriptKind::EncodedJScript] {
        let report = verify(&data, kind);
        assert_eq!(report.signing_state, ScriptSigningState::Unsigned);
        assert_eq!(report.warnings, vec![ScriptWarning::UnsupportedEncoding]);
        assert!(report.encoding.is_none());
        assert!(report.sip_digests.is_none());
        assert!(kind.is_encoded());
    }
    assert_eq!(
        ScriptKind::from_extension("VBE"),
        Some(ScriptKind::EncodedVbScript)
    );
}

#[test]
fn size_limit() {
    let data = fixture("ps1-utf8-crlf.ps1");
    let small = ScriptOptions {
        max_size: data.len() as u64 - 1,
        ..ScriptOptions::default()
    };
    let report = verify_script(&data, ScriptKind::PowerShell, &small);
    assert_eq!(
        report.signing_state,
        ScriptSigningState::TooLargeForSignatureCheck {
            size: data.len() as u64,
            limit: data.len() as u64 - 1
        }
    );
    assert!(report.signatures.signatures.is_empty());
    assert_eq!(ScriptOptions::default().max_size, DEFAULT_MAX_SCRIPT_SIZE);
    assert_eq!(DEFAULT_MAX_SCRIPT_SIZE, 32 * 1024 * 1024);

    // From a file: not read when over the limit, and read when within it.
    let path = Path::new(FIXTURES).join("ps1-utf8-crlf.ps1");
    let report = verify_script_file(&path, ScriptKind::PowerShell, &small).unwrap();
    assert!(matches!(
        report.signing_state,
        ScriptSigningState::TooLargeForSignatureCheck { .. }
    ));
    let report =
        verify_script_file(&path, ScriptKind::PowerShell, &ScriptOptions::default()).unwrap();
    assert_eq!(report.signing_state, ScriptSigningState::Valid);
}

#[test]
fn extensions() {
    for (ext, kind) in [
        ("ps1", ScriptKind::PowerShell),
        ("PSM1", ScriptKind::PowerShell),
        ("psd1", ScriptKind::PowerShell),
        ("ps1xml", ScriptKind::PowerShellXml),
        ("psc1", ScriptKind::PowerShellXml),
        ("cdxml", ScriptKind::PowerShellXml),
        ("mof", ScriptKind::Mof),
        ("vbs", ScriptKind::VbScript),
        ("js", ScriptKind::JScript),
        ("wsf", ScriptKind::WindowsScriptFile),
        ("jse", ScriptKind::EncodedJScript),
    ] {
        assert_eq!(ScriptKind::from_extension(ext), Some(kind), "{ext}");
    }
    assert_eq!(ScriptKind::from_extension("exe"), None);
    assert_eq!(ScriptKind::from_path(Path::new("noext")), None);
}

// ---------------------------------------------------------------------------
// Trust.

#[test]
fn trust_anchor_policy() {
    let signer = Signer::new();
    let data = sign_ps1(&signer, BODY, &[metadata_attr(4, &utf8("Palisade Tools"))]);
    let report = verify(&data, ScriptKind::PowerShell);
    let anchored = signer.trust();
    let empty = TrustConfig::new();
    let eval = |policy_set: &TrustConfig, os: Option<&TrustConfig>, policy| {
        evaluate_script_trust(
            &report,
            &ScriptTrustAnchors {
                policy: policy_set,
                os_root_store: os,
            },
            policy,
        )
    };
    use ScriptAnchorPolicy::{Either, OsRootStore, PolicyAnchors};
    use ScriptAnchorSource as S;
    for (policy_set, os, policy, expected) in [
        (&anchored, None, PolicyAnchors, Some(S::PolicyAnchors)),
        (&anchored, None, OsRootStore, None),
        (&anchored, None, Either, Some(S::PolicyAnchors)),
        (&empty, Some(&anchored), PolicyAnchors, None),
        (&empty, Some(&anchored), OsRootStore, Some(S::OsRootStore)),
        (&empty, Some(&anchored), Either, Some(S::OsRootStore)),
        (&anchored, Some(&anchored), Either, Some(S::PolicyAnchors)),
        (&empty, Some(&empty), Either, None),
    ] {
        let trust = eval(policy_set, os, policy);
        assert_eq!(trust.anchor, expected, "{policy:?}");
        assert_eq!(trust.policy, policy);
        assert_eq!(trust.signed_metadata.is_some(), expected.is_some());
        assert_eq!(trust.publisher_product.is_some(), expected.is_some());
        if expected.is_none() {
            assert_eq!(trust.trust.primary, None);
            assert!(
                trust.trust.signers[0]
                    .untrusted
                    .contains(&UntrustedReason::NoTrustAnchor),
                "{:?}",
                trust.trust.signers[0].untrusted
            );
        }
    }
    assert_eq!(ScriptAnchorPolicy::default(), Either);
}

#[test]
fn a_changed_script_is_never_trusted() {
    let signer = Signer::new();
    let data = sign_ps1(&signer, BODY, &[metadata_attr(4, &utf8("Palisade Tools"))]);
    let changed = verify(&tamper_text(&data), ScriptKind::PowerShell);
    assert_eq!(changed.signing_state, ScriptSigningState::DigestMismatch);
    let policy = signer.trust();
    let trust = evaluate_script_trust(
        &changed,
        &ScriptTrustAnchors {
            policy: &policy,
            os_root_store: Some(&policy),
        },
        ScriptAnchorPolicy::Either,
    );
    assert_eq!(trust.anchor, None);
    assert_eq!(trust.signed_metadata, None);
    // Even with the tolerate knob, which exposes signer attributes as
    // untrusted.
    let tolerant = ScriptOptions {
        verify: palisade_fileid::authenticode::VerifyOptions {
            tolerate_digest_mismatch: true,
        },
        ..ScriptOptions::default()
    };
    let changed = verify_script(&tamper_text(&data), ScriptKind::PowerShell, &tolerant);
    assert!(changed.signature().unwrap().untrusted_signer_attrs);
    assert_eq!(changed.signing_state, ScriptSigningState::DigestMismatch);
    assert_eq!(
        changed.signatures.warnings,
        vec![
            palisade_fileid::authenticode::ReportWarning::DigestMismatchTolerated { signature: 0 }
        ]
    );
    let trust = evaluate_script_trust(
        &changed,
        &ScriptTrustAnchors {
            policy: &policy,
            os_root_store: Some(&policy),
        },
        ScriptAnchorPolicy::Either,
    );
    assert_eq!(trust.anchor, None);
}

fn tamper_text(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let at = find(data, b"palisade");
    out[at] = b'P';
    out
}

#[test]
fn signature_digest_algorithm_is_recorded() {
    let report = verify(&fixture("js-utf8-crlf.js"), ScriptKind::JScript);
    let sig = report.signature().unwrap();
    assert_eq!(sig.digest_alg, Some(DigestAlgorithm::Sha256));
    assert_eq!(sig.signer_digest_alg, Some(DigestAlgorithm::Sha256));
    assert!(!sig.os_ci_compatible(), "an ECDSA signer");
}

// ---------------------------------------------------------------------------
// The OS, as a differential check (Windows only).

/// On Windows, the OS's own verdict on every fixture and on a copy with
/// one character changed: whenever this crate says a script is validly
/// signed the OS must not report a hash mismatch or no signature, and
/// whenever this crate says the digest does not match, the OS must say so
/// too. Trust is not compared: the fixtures' root is in no store.
#[cfg(windows)]
#[test]
fn os_trust_verification_agrees() {
    let dir = std::env::temp_dir().join(format!("palisade-script-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cases = Vec::new();
    for name in fixture_names() {
        let data = fixture(&name);
        let original = dir.join(&name);
        std::fs::write(&original, &data).unwrap();
        let tampered = dir.join(format!("tampered-{name}"));
        std::fs::write(&tampered, tamper(&data)).unwrap();
        cases.push((original, verify(&data, kind_of(&name)).signing_state));
        cases.push((
            tampered,
            verify(&tamper(&data), kind_of(&name)).signing_state,
        ));
    }
    let list = dir.join("paths.txt");
    let paths: Vec<String> = cases.iter().map(|(p, _)| p.display().to_string()).collect();
    std::fs::write(&list, paths.join("\r\n")).unwrap();
    let script = format!(
        "Get-Content -Encoding UTF8 -LiteralPath '{}' | ForEach-Object {{ \
         (Get-AuthenticodeSignature -LiteralPath $_).Status.ToString() }}",
        list.display()
    );
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let statuses: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(statuses.len(), cases.len(), "{statuses:?}");
    for ((path, ours), os) in cases.iter().zip(&statuses) {
        match ours {
            ScriptSigningState::Valid => assert!(
                os != "HashMismatch" && os != "NotSigned" && os != "Incompatible",
                "{}: valid here, {os} for the OS",
                path.display()
            ),
            ScriptSigningState::DigestMismatch => {
                assert_eq!(os, "HashMismatch", "{}", path.display());
            }
            other => panic!("{}: unexpected {other:?}", path.display()),
        }
    }
}

// ---------------------------------------------------------------------------
// Properties.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No input panics, and only a script whose block verifies is valid.
    #[test]
    fn arbitrary_input_is_never_valid(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        for kind in [ScriptKind::PowerShell, ScriptKind::VbScript, ScriptKind::WindowsScriptFile] {
            let report = verify(&data, kind);
            prop_assert_ne!(&report.signing_state, &ScriptSigningState::Valid);
            prop_assert!(report.signatures.signatures.len() <= 1);
        }
    }

    /// Any one-byte change to a signed script, outside the base64 data
    /// (the text, the marker lines, the comment prefixes and every line
    /// break), leaves it anything but validly signed.
    #[test]
    fn one_byte_changes_are_never_valid(index in 0_usize..4096, byte in any::<u8>()) {
        let data = fixture("ps1-utf8bom-crlf.ps1");
        let outside: Vec<usize> = (0..data.len()).filter(|i| !is_base64_data(&data, *i)).collect();
        let at = outside[index % outside.len()];
        prop_assume!(data[at] != byte);
        let mut changed = data.clone();
        changed[at] = byte;
        let report = verify(&changed, ScriptKind::PowerShell);
        prop_assert_ne!(report.signing_state, ScriptSigningState::Valid);
    }

    /// Any one-byte change to the base64 data leaves the script either not
    /// validly signed, or validly signed but untrusted, or exactly as
    /// trusted as before with the same signer, digest and attributes: a
    /// change to a certificate the chain does not use (the embedded root,
    /// when the policy holds it) changes nothing that is relied on.
    #[test]
    fn one_byte_changes_to_the_signature_are_never_trusted_differently(
        index in 0_usize..4096,
        byte in any::<u8>(),
    ) {
        let data = fixture("ps1-utf8bom-crlf.ps1");
        let inside: Vec<usize> = (0..data.len()).filter(|i| is_base64_data(&data, *i)).collect();
        let at = inside[index % inside.len()];
        prop_assume!(data[at] != byte);
        let mut changed = data.clone();
        changed[at] = byte;
        let report = verify(&changed, ScriptKind::PowerShell);
        let mut config = TrustConfig::new();
        config.add_anchor("fixture root", &fixture("ca.der")).unwrap();
        let anchors = ScriptTrustAnchors { policy: &config, os_root_store: None };
        let trust = evaluate_script_trust(&report, &anchors, ScriptAnchorPolicy::PolicyAnchors);
        if trust.anchor.is_some() {
            let original = verify(&data, ScriptKind::PowerShell);
            let before = original.signature().unwrap();
            let after = report.signature().unwrap();
            prop_assert_eq!(&before.signed_image_digest, &after.signed_image_digest);
            prop_assert_eq!(&before.signature_value, &after.signature_value);
            let signer = |s: &palisade_fileid::authenticode::SignatureInfo| {
                s.signer.as_ref().map(|a| s.certs_in_blob[a.signer_cert].clone())
            };
            prop_assert_eq!(signer(before), signer(after));
        }
    }

    /// Truncating a signed script anywhere never leaves it valid.
    #[test]
    fn truncation_is_never_valid(cut in 0_usize..4096) {
        let data = fixture("wsf-utf16le-crlf.wsf");
        let cut = cut % data.len();
        let report = verify(&data[..cut], ScriptKind::WindowsScriptFile);
        prop_assert_ne!(report.signing_state, ScriptSigningState::Valid);
    }
}

/// Whether byte `at` of a PowerShell fixture is a base64 character of a
/// block data line.
fn is_base64_data(data: &[u8], at: usize) -> bool {
    let start = block_start(data);
    if at < start {
        return false;
    }
    let line_start = data[..at]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |p| p + 1);
    let line = &data[line_start..];
    let line = &line[..line.iter().position(|b| *b == b'\r').unwrap_or(line.len())];
    line.starts_with(b"# ")
        && !line.starts_with(b"# SIG #")
        && at >= line_start + 2
        && at < line_start + line.len()
}

// ---------------------------------------------------------------------------
// Fuzz seeds.

/// Writes the fixtures, and scripts signed here, as seed inputs for the
/// `script_sig` fuzz target. The target reads the first byte as the
/// format, so each seed is a format byte and a script.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR=/tmp/seeds cargo test -p palisade-fileid --test script \
///   -- --ignored --exact write_script_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_script_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let format_byte = |kind: ScriptKind| match kind {
        ScriptKind::PowerShell => 0_u8,
        ScriptKind::PowerShellXml => 1,
        ScriptKind::Mof => 2,
        ScriptKind::VbScript => 3,
        ScriptKind::JScript => 4,
        ScriptKind::WindowsScriptFile => 5,
        _ => 6,
    };
    for name in fixture_names() {
        let mut seed = vec![format_byte(kind_of(&name))];
        seed.extend_from_slice(&fixture(&name));
        std::fs::write(dir.join(format!("seed-{name}")), seed).unwrap();
    }
    let signer = Signer::new();
    let mut seed = vec![0];
    seed.extend_from_slice(&sign_ps1(
        &signer,
        BODY,
        &[metadata_attr(4, &utf8("Palisade Tools"))],
    ));
    std::fs::write(dir.join("seed-metadata.ps1"), seed).unwrap();
}
