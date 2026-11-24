//! Script signature blocks (#52): the embedded Authenticode signatures of
//! PowerShell, VBScript, JScript and Windows Script Files, and the signed
//! metadata attributes that give such files version-like identity.
//!
//! A signed script carries its PKCS#7 SignedData as base64 in comment lines
//! at the end of the text (for a Windows Script File, in a `<signature>`
//! element before the last `</job>`). The SignedData is the same
//! Authenticode structure a PE file carries, except that its indirect data
//! is `SPC_SIPINFO` (1.3.6.1.4.1.311.2.1.30), naming the subject interface
//! package (SIP) that hashed the text, and its digest is that package's
//! digest of the script.
//!
//! - [`verify_script`] finds and checks the block, computes the digest the
//!   way the OS package does, and verifies the signature with the same
//!   machinery as PE signatures (#48): the strict DER reader, the
//!   SignedData decoder, the signer certificate lookup, the `messageDigest`
//!   check and the signature over the authenticated attributes. The result
//!   is a [`ScriptReport`], whose [`ScriptReport::signatures`] holds at most
//!   one [`SignatureKind::Script`] signature that
//!   [`crate::authenticode::evaluate_trust`] and
//!   [`crate::authenticode::evaluate_validity`] take like any other.
//! - [`evaluate_script_trust`] decides trust under a
//!   [`ScriptAnchorPolicy`]: the OS requires a script's root to be in the
//!   machine root store, unlike a PE file's.
//! - [`crate::authenticode::SignedMetadata`] holds the signed metadata
//!   attributes (1.3.6.1.4.1.311.2.7.1 to .10). They are read from every
//!   signature, PE ones included, into
//!   [`crate::authenticode::SignerAttributes::signed_metadata`].
//!
//! # The digest
//!
//! Both kinds of package hash the script as UTF-16LE text, without the
//! signature block and the line break before it:
//!
//! | Package | Formats | Byte order mark | Appended |
//! |---|---|---|---|
//! | PowerShell | `.ps1 .psm1 .psd1`, `.ps1xml .psc1 .cdxml`, `.mof` | hashed, as U+FEFF | nothing |
//! | Windows Script Host | `.vbs`, `.js`, `.wsf` | not hashed | the block's position, in UTF-16 units of the hashed text, as a 32-bit little-endian integer |
//!
//! For `.wsf`, the text after the block (the closing `</job>`) is hashed
//! too. The text is decoded by its byte order mark: UTF-8, UTF-16LE or
//! UTF-16BE (the PowerShell package does not sign UTF-16BE). Line endings
//! are hashed as they are: an LF file and a CRLF file have different
//! digests. These rules are checked against scripts signed by OS tooling
//! in every format, encoding and line-ending combination, and against
//! signed scripts the OS ships (`tests/script.rs`).
//!
//! # Failing conservative
//!
//! A script's signature is untrusted input, and interpreters read text in
//! more ways than one. So anything ambiguous, truncated or lossy fails the
//! check, and never makes a file look signed:
//!
//! - **Text without a byte order mark** is decoded by the OS from a guess,
//!   falling back to the machine's code page, so its digest depends on the
//!   machine. It is read only when it is ASCII without NUL, which every
//!   candidate decodes the same way; otherwise [`TextIssue`].
//! - Invalid UTF-8 after a UTF-8 byte order mark, unpaired surrogates or an
//!   odd length in UTF-16 text, a UTF-32 byte order mark, and UTF-16BE
//!   PowerShell text are [`TextIssue`]s too.
//! - The block must be exactly as signers write it: one begin line and one
//!   end line, each a whole line; a CRLF before the begin line; every line
//!   ending in CRLF; every data line the format's comment prefix, strict
//!   base64 and the comment suffix; and nothing after the end line except,
//!   for `.wsf`, the rest of the file. Anything else is a [`BlockError`].
//!   The exact marker text anywhere else in the file, even inside a string,
//!   is one too ([`BlockError::MultipleBlocks`]), because another reader
//!   could take it for the block. Marker text that differs from the
//!   format's in case or spacing is not marker text, so such a file is
//!   unsigned.
//! - The base64 must decode to exactly one DER SignedData whose `SpcSipInfo`
//!   names the format's package. Nested signatures are checked as DER but
//!   not verified ([`ScriptWarning::NestedSignaturesIgnored`]).
//! - Encoded scripts (`.vbe`, `.jse`) are not read at all: they are
//!   unsigned, with [`ScriptWarning::UnsupportedEncoding`].
//! - Files over [`ScriptOptions::max_size`] are not read:
//!   [`ScriptSigningState::TooLargeForSignatureCheck`].
//!
//! # Not done here yet
//!
//! - Reading the OS machine root store, and the OS trust-verification
//!   cross-check, need the Windows API (`os-trust`, #48 and #95). The
//!   caller supplies the root store as a [`TrustConfig`].
//! - Catalog-signed scripts: [`ScriptReport::catalog_digests`] is the hook
//!   for a [`crate::catalog::CatalogStore`] lookup; matching against
//!   catalogs made by OS tooling, and folding a match into the file's
//!   signing state, are #51 and #55.
//! - Feeding the signed metadata into the unified file identity record is
//!   #55; interpreter enforcement is #92 to #95.

#![forbid(unsafe_code)]

mod text;

use std::fmt;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use crate::authenticode::asn1;
use crate::authenticode::pkcs7;
use crate::authenticode::verify::check;
use crate::authenticode::{
    AuthenticodeHashes, AuthenticodeStatus, InvalidReason, ReportWarning, SignatureError,
    SignatureInfo, SignatureKind, SignatureReport, SignatureStatus, SignedMetadata, SigningState,
    TrustConfig, TrustReport, VerifyOptions, evaluate_trust,
};
use crate::catalog::FileDigests;
use crate::hash::{AlgorithmSet, Digest, FlatHashes, HashAlgorithm};

pub use text::MAX_SIGNATURE_SIZE;

/// The default largest script whose signature is checked: 32 MiB.
pub const DEFAULT_MAX_SCRIPT_SIZE: u64 = 32 * 1024 * 1024;

/// A script format, by the subject interface package that signs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScriptKind {
    /// PowerShell scripts, modules and data files (`.ps1`, `.psm1`,
    /// `.psd1`): `# SIG # Begin signature block` comment lines.
    PowerShell,
    /// PowerShell XML files (`.ps1xml`, `.psc1`, `.cdxml`):
    /// `<!-- SIG # Begin signature block -->` comment lines.
    PowerShellXml,
    /// Managed object format files (`.mof`), signed by the PowerShell
    /// package: `/* SIG # Begin signature block */` comment lines.
    Mof,
    /// VBScript (`.vbs`): `'' SIG '' Begin signature block` lines.
    VbScript,
    /// JScript (`.js`): `// SIG // Begin signature block` lines.
    JScript,
    /// Windows Script Files (`.wsf`): a `<signature>` element of
    /// `** SIG **` lines.
    WindowsScriptFile,
    /// Encoded VBScript (`.vbe`). Not read: always unsigned, with
    /// [`ScriptWarning::UnsupportedEncoding`].
    EncodedVbScript,
    /// Encoded JScript (`.jse`). Not read: always unsigned, with
    /// [`ScriptWarning::UnsupportedEncoding`].
    EncodedJScript,
}

impl ScriptKind {
    /// The kind a file extension (without the dot, any case) names.
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "ps1" | "psm1" | "psd1" => Self::PowerShell,
            "ps1xml" | "psc1" | "cdxml" => Self::PowerShellXml,
            "mof" => Self::Mof,
            "vbs" => Self::VbScript,
            "js" => Self::JScript,
            "wsf" => Self::WindowsScriptFile,
            "vbe" => Self::EncodedVbScript,
            "jse" => Self::EncodedJScript,
            _ => return None,
        })
    }

    /// The kind `path`'s extension names.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        Self::from_extension(path.extension()?.to_str()?)
    }

    /// Whether the format is an encoded script, which is never read.
    #[must_use]
    pub const fn is_encoded(self) -> bool {
        matches!(self, Self::EncodedVbScript | Self::EncodedJScript)
    }

    /// The block format, or `None` for an encoded script.
    fn style(self) -> Option<&'static Style> {
        match self {
            Self::PowerShell => Some(&POWERSHELL),
            Self::PowerShellXml => Some(&POWERSHELL_XML),
            Self::Mof => Some(&MOF),
            Self::VbScript => Some(&VBSCRIPT),
            Self::JScript => Some(&JSCRIPT),
            Self::WindowsScriptFile => Some(&WSF),
            Self::EncodedVbScript | Self::EncodedJScript => None,
        }
    }
}

/// How one format writes its block, and how its package hashes the text.
#[derive(Debug)]
pub(crate) struct Style {
    /// The begin line.
    begin: &'static str,
    /// The end line.
    end: &'static str,
    /// Before the base64 on each data line.
    prefix: &'static str,
    /// After the base64 on each data line.
    suffix: &'static str,
    /// Whether a byte order mark is hashed (as U+FEFF).
    hashes_bom: bool,
    /// Whether the block's position is appended to the hashed text.
    hashes_position: bool,
    /// Whether text may follow the block (and is then hashed).
    allows_text_after: bool,
    /// Whether the package signs UTF-16BE text.
    allows_utf16be: bool,
    /// `SpcSipInfo.dwSIPversion`.
    sip_version: u32,
    /// `SpcSipInfo.gSIPguid`, as encoded.
    sip_guid: [u8; 16],
}

/// The PowerShell package's GUID, as encoded.
const POWERSHELL_SIP: [u8; 16] = [
    0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51,
];

const fn powershell(
    begin: &'static str,
    end: &'static str,
    prefix: &'static str,
    suffix: &'static str,
) -> Style {
    Style {
        begin,
        end,
        prefix,
        suffix,
        hashes_bom: true,
        hashes_position: false,
        allows_text_after: false,
        allows_utf16be: false,
        sip_version: 0x0001_0000,
        sip_guid: POWERSHELL_SIP,
    }
}

const fn script_host(
    begin: &'static str,
    end: &'static str,
    prefix: &'static str,
    allows_text_after: bool,
    sip_guid: [u8; 16],
) -> Style {
    Style {
        begin,
        end,
        prefix,
        suffix: "",
        hashes_bom: false,
        hashes_position: true,
        allows_text_after,
        allows_utf16be: true,
        sip_version: 1,
        sip_guid,
    }
}

const POWERSHELL: Style = powershell(
    "# SIG # Begin signature block",
    "# SIG # End signature block",
    "# ",
    "",
);
const POWERSHELL_XML: Style = powershell(
    "<!-- SIG # Begin signature block -->",
    "<!-- SIG # End signature block -->",
    "<!-- ",
    " -->",
);
const MOF: Style = powershell(
    "/* SIG # Begin signature block */",
    "/* SIG # End signature block */",
    "/* ",
    " */",
);
const VBSCRIPT: Style = script_host(
    "'' SIG '' Begin signature block",
    "'' SIG '' End signature block",
    "'' SIG '' ",
    false,
    [
        0x4e, 0xf0, 0x29, 0x16, 0x99, 0x27, 0xb5, 0x4d, 0x8f, 0xe5, 0xac, 0xe1, 0x0f, 0x17, 0xeb,
        0xab,
    ],
);
const JSCRIPT: Style = script_host(
    "// SIG // Begin signature block",
    "// SIG // End signature block",
    "// SIG // ",
    false,
    [
        0x10, 0xe0, 0xc9, 0x06, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0x00, 0x10, 0x4b, 0xd3, 0x50,
        0x90,
    ],
);
const WSF: Style = script_host(
    "<signature>",
    "</signature>",
    "** SIG ** ",
    true,
    [
        0x70, 0x05, 0x61, 0x1a, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0x00, 0x10, 0x4b, 0xd3, 0x50,
        0x90,
    ],
);

/// How a script's text is encoded, by its byte order mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TextEncoding {
    /// No byte order mark.
    NoBom,
    /// UTF-8 with a byte order mark.
    Utf8Bom,
    /// UTF-16LE (with its byte order mark).
    Utf16Le,
    /// UTF-16BE (with its byte order mark).
    Utf16Be,
}

/// Why a script's text cannot be decoded without ambiguity. A script with
/// one of these can be unsigned, but never validly signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TextIssue {
    /// Text without a byte order mark has a byte outside ASCII. The OS
    /// decodes it by a guess, or by the machine's code page, so its digest
    /// depends on the machine.
    NonAsciiWithoutBom,
    /// Text without a byte order mark has a NUL byte, so it could be taken
    /// for UTF-16.
    NulWithoutBom,
    /// Text after a UTF-8 byte order mark is not valid UTF-8.
    InvalidUtf8,
    /// UTF-16 text has an odd number of bytes.
    OddUtf16Length,
    /// UTF-16 text has an unpaired surrogate.
    UnpairedSurrogate,
    /// The file starts with a UTF-32LE byte order mark.
    Utf32Bom,
    /// UTF-16BE text, which the PowerShell package does not sign.
    Utf16BeNotSigned,
}

/// Why a signature block is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BlockError {
    /// The begin or end marker text occurs more than once anywhere in the
    /// file, not only as a whole line.
    MultipleBlocks,
    /// An end line, but no begin line.
    MissingBegin,
    /// A begin line, but no end line.
    MissingEnd,
    /// The begin line is not preceded by a CRLF (it starts the file, or
    /// follows a bare LF).
    NoLineBreakBefore,
    /// A line of the block (0 is the begin line) does not end in CRLF.
    BadLineEnding {
        /// The line, counted from the begin line.
        line: usize,
    },
    /// The end line has no line break after it.
    Unterminated,
    /// A data line is not the format's prefix, base64 and suffix.
    BadLine {
        /// The line, counted from the begin line.
        line: usize,
    },
    /// The block has no data lines.
    Empty,
    /// Text follows the end line, in a format where the block must end the
    /// file.
    NotAtEnd,
    /// The base64 would decode to more than [`MAX_SIGNATURE_SIZE`] bytes.
    TooLarge,
    /// The joined base64 is not strict base64.
    Base64,
    /// Bytes follow the SignedData in the decoded block.
    TrailingData,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleBlocks => f.write_str("more than one signature block"),
            Self::MissingBegin => f.write_str("a signature block end with no beginning"),
            Self::MissingEnd => f.write_str("a signature block with no end"),
            Self::NoLineBreakBefore => f.write_str("the signature block is not preceded by a CRLF"),
            Self::BadLineEnding { line } => write!(f, "block line {line} does not end in CRLF"),
            Self::Unterminated => f.write_str("the block's end line has no line break"),
            Self::BadLine { line } => write!(f, "block line {line} is not a signature line"),
            Self::Empty => f.write_str("the signature block is empty"),
            Self::NotAtEnd => f.write_str("text follows the signature block"),
            Self::TooLarge => write!(f, "the signature exceeds {MAX_SIGNATURE_SIZE} bytes"),
            Self::Base64 => f.write_str("the signature block is not valid base64"),
            Self::TrailingData => f.write_str("bytes follow the signature in the block"),
        }
    }
}

/// Why a signed script is not validly signed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptInvalidReason {
    /// The text cannot be decoded without ambiguity.
    Text(TextIssue),
    /// The signature block is not well formed.
    Block(BlockError),
    /// The signature is not valid; its status. A changed script is
    /// [`ScriptSigningState::DigestMismatch`] instead.
    Signature(SignatureStatus),
}

/// A script's signing state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptSigningState {
    /// No signature block (or an encoded script, which is not read).
    Unsigned,
    /// The signature is valid. Trust is [`evaluate_script_trust`].
    Valid,
    /// The signature is valid, but the script changed after signing.
    DigestMismatch,
    /// The script carries a signature, or something like one, that is not
    /// valid.
    Invalid(ScriptInvalidReason),
    /// The file is larger than [`ScriptOptions::max_size`], so it was not
    /// read.
    TooLargeForSignatureCheck {
        /// The file's size.
        size: u64,
        /// The limit.
        limit: u64,
    },
}

/// Something unusual about a script that does not change its state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScriptWarning {
    /// An encoded script, which is not read: it is reported unsigned.
    UnsupportedEncoding,
    /// The signer carries this many nested signatures (counted up to the
    /// collection limit). They are checked as DER, but not verified: only
    /// the outer signature counts.
    NestedSignaturesIgnored(usize),
}

/// Where the signature block is: the CRLF before its begin line through
/// the line break after its end line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BlockLocation {
    /// Its file offset.
    pub offset: u64,
    /// Its length in bytes.
    pub len: u64,
}

/// Options for [`verify_script`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptOptions {
    /// The largest file read. Default [`DEFAULT_MAX_SCRIPT_SIZE`].
    pub max_size: u64,
    /// As for PE signatures.
    pub verify: VerifyOptions,
}

impl Default for ScriptOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SCRIPT_SIZE,
            verify: VerifyOptions::default(),
        }
    }
}

/// A script's signature, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptReport {
    /// The format it was read as.
    pub kind: ScriptKind,
    /// The file's size in bytes.
    pub size: u64,
    /// The text encoding. `None` when the file was not read.
    pub encoding: Option<TextEncoding>,
    /// Why the text cannot be decoded without ambiguity, if it cannot. The
    /// digests are then `None`.
    pub text_issue: Option<TextIssue>,
    /// The signing state.
    pub signing_state: ScriptSigningState,
    /// The signature block, when it is well formed.
    pub block: Option<BlockLocation>,
    /// At most one [`SignatureKind::Script`] signature, present when the
    /// block decodes; for [`crate::authenticode::evaluate_trust`] and
    /// [`crate::authenticode::evaluate_validity`]. It has no
    /// `WIN_CERTIFICATE` entries, and its `image_status` is always
    /// conformant.
    pub signatures: SignatureReport,
    /// The package's digests of the text without the block (SHA-256,
    /// SHA-1 and the signature's own algorithm): what the signature, or a
    /// catalog, signs. `None` when the text was not read or does not
    /// decode, and for an unsigned `.wsf`, whose block position the package
    /// would choose.
    pub sip_digests: Option<FlatHashes>,
    /// `script_hash_normalised`: the SHA-256 of the UTF-8 text without the
    /// block and its preceding line break, without the byte order mark,
    /// and with every CRLF and lone CR turned into LF. A **tolerant**
    /// identity (weak-medium), for explicit opt-in rules only: it stays the
    /// same when a script is re-encoded, its line endings change, or it is
    /// signed or re-signed. The flat hash stays the default identity.
    /// `None` when the text was not read or does not decode.
    pub normalised_hash: Option<Digest>,
    /// Anything unusual.
    pub warnings: Vec<ScriptWarning>,
}

impl ScriptReport {
    /// The script's signature, if the block decoded.
    #[must_use]
    pub fn signature(&self) -> Option<&SignatureInfo> {
        self.signatures.signatures.first()
    }

    /// The digests to look a script up in a
    /// [`crate::catalog::CatalogStore`] with: the package digests, as the
    /// non-PE (flat) digests a catalog lists a script under. Matching them
    /// against catalogs made by OS tooling is still to be checked (#51), so
    /// a miss does not show that no catalog lists the script.
    #[must_use]
    pub fn catalog_digests(&self) -> FileDigests {
        let get = |alg| self.sip_digests.as_ref()?.get(alg).cloned();
        FileDigests {
            flat_sha256: get(HashAlgorithm::Sha256),
            flat_sha1: get(HashAlgorithm::Sha1),
            ..FileDigests::default()
        }
    }
}

fn empty_signatures() -> SignatureReport {
    SignatureReport {
        entries: Vec::new(),
        signatures: Vec::new(),
        primary: None,
        signing_state: SigningState::Unsigned,
        tolerate_digest_mismatch: false,
        image_status: AuthenticodeStatus::Conformant,
        warnings: Vec::new(),
    }
}

/// A report for a file that was not read.
fn not_read(kind: ScriptKind, options: &ScriptOptions) -> ScriptReport {
    ScriptReport {
        kind,
        size: 0,
        encoding: None,
        text_issue: None,
        signing_state: ScriptSigningState::Unsigned,
        block: None,
        signatures: SignatureReport {
            tolerate_digest_mismatch: options.verify.tolerate_digest_mismatch,
            ..empty_signatures()
        },
        sip_digests: None,
        normalised_hash: None,
        warnings: Vec::new(),
    }
}

/// Reads the script `data` as `kind` and checks its signature block.
#[must_use]
pub fn verify_script(data: &[u8], kind: ScriptKind, options: &ScriptOptions) -> ScriptReport {
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let mut report = ScriptReport {
        size,
        ..not_read(kind, options)
    };
    if size > options.max_size {
        report.signing_state = ScriptSigningState::TooLargeForSignatureCheck {
            size,
            limit: options.max_size,
        };
        return report;
    }
    let Some(style) = kind.style() else {
        report.warnings.push(ScriptWarning::UnsupportedEncoding);
        return report;
    };

    let (text, mut issue) = text::Text::new(data);
    if issue.is_none() && text.encoding == TextEncoding::Utf16Be && !style.allows_utf16be {
        issue = Some(TextIssue::Utf16BeNotSigned);
    }
    report.encoding = Some(text.encoding);
    report.text_issue = issue;

    // Find the block. Markers are compared as exact ASCII text, which is
    // exact in every encoding read here.
    let invalid = ScriptSigningState::Invalid;
    let block = match (text.count(style.begin), text.count(style.end)) {
        (0, 0) => None,
        (b, e) if b > 1 || e > 1 => {
            report.signing_state = invalid(ScriptInvalidReason::Block(BlockError::MultipleBlocks));
            return report;
        }
        (0, _) => {
            report.signing_state = invalid(ScriptInvalidReason::Block(BlockError::MissingBegin));
            return report;
        }
        _ => {
            if let Some(issue) = issue {
                report.signing_state = invalid(ScriptInvalidReason::Text(issue));
                return report;
            }
            let parsed = text
                .find(style.begin)
                .ok_or(BlockError::MissingEnd)
                .and_then(|at| text.parse_block(at, style));
            match parsed {
                Ok(block) => Some(block),
                Err(e) => {
                    report.signing_state = invalid(ScriptInvalidReason::Block(e));
                    return report;
                }
            }
        }
    };
    if issue.is_some() {
        return report;
    }

    let Some(block) = block else {
        // Unsigned: the digests a catalog would list it under. A `.wsf`
        // has no defined block position until a signer places one.
        let digests = text.digests(None, style, AlgorithmSet::SHA256 | AlgorithmSet::SHA1);
        if !style.allows_text_after {
            report.sip_digests = digests.sip;
        }
        report.normalised_hash = digests.normalised;
        return report;
    };
    report.block = Some(BlockLocation {
        offset: text.byte_offset(block.start),
        len: text
            .byte_offset(block.end)
            .saturating_sub(text.byte_offset(block.start)),
    });

    let der = match text::decode_base64(&block.payload) {
        Some(der) => der,
        None => {
            report.signing_state = invalid(ScriptInvalidReason::Block(BlockError::Base64));
            return report;
        }
    };
    let signed = match parse_signature(&der, style) {
        Ok(signed) => signed,
        Err(Parse::Block(e)) => {
            report.signing_state = invalid(ScriptInvalidReason::Block(e));
            return report;
        }
        Err(Parse::Signature(e)) => {
            let info = SignatureInfo {
                kind: SignatureKind::Script,
                total: 1,
                ..crate::authenticode::verify::blank(SignatureStatus::Malformed(e.clone()))
            };
            report.signatures.signing_state = SigningState::Invalid(InvalidReason::Signature(
                SignatureStatus::Malformed(e.clone()),
            ));
            report.signatures.signatures.push(info);
            report.signing_state = invalid(ScriptInvalidReason::Signature(
                SignatureStatus::Malformed(e),
            ));
            return report;
        }
    };

    let mut algorithms = AlgorithmSet::SHA256 | AlgorithmSet::SHA1;
    if let Some(alg) = signed
        .indirect
        .digest_alg
        .as_ref()
        .ok()
        .and_then(|a| a.hash_algorithm())
    {
        algorithms.insert(alg);
    }
    let digests = text.digests(Some(&block), style, algorithms);
    report.normalised_hash = digests.normalised;
    let script_digests = AuthenticodeHashes {
        digests: digests
            .sip
            .as_ref()
            .map(|d| d.digests.clone())
            .unwrap_or_default(),
        hashed_bytes: digests.sip.as_ref().map_or(0, |d| d.size),
        status: AuthenticodeStatus::Conformant,
        page_hashes: None,
    };
    report.sip_digests = digests.sip;

    if !signed.signer.nested.is_empty() {
        report.warnings.push(ScriptWarning::NestedSignaturesIgnored(
            signed.signer.nested.len(),
        ));
    }
    let info = SignatureInfo {
        kind: SignatureKind::Script,
        total: 1,
        ..check(&signed, &script_digests, &options.verify)
    };
    if info.untrusted_signer_attrs {
        report
            .signatures
            .warnings
            .push(ReportWarning::DigestMismatchTolerated { signature: 0 });
    }
    report.signing_state = match &info.status {
        SignatureStatus::Valid => ScriptSigningState::Valid,
        SignatureStatus::DigestMismatch => ScriptSigningState::DigestMismatch,
        other => invalid(ScriptInvalidReason::Signature(other.clone())),
    };
    let valid = info.status.is_valid();
    report.signatures.signing_state = if valid {
        SigningState::Valid
    } else {
        SigningState::Invalid(InvalidReason::Signature(info.status.clone()))
    };
    report.signatures.primary = valid.then_some(0);
    report.signatures.signatures.push(info);
    report
}

/// Why a decoded block is not a script signature.
enum Parse {
    Block(BlockError),
    Signature(SignatureError),
}

/// Decodes the block's DER: exactly one SignedData, DER throughout
/// (nested signatures included), signing indirect data whose `SpcSipInfo`
/// names `style`'s package.
fn parse_signature<'a>(der: &'a [u8], style: &Style) -> Result<pkcs7::SignedData<'a>, Parse> {
    let (signed, sip, trailing) =
        pkcs7::parse_sip_content_info(der, 0).map_err(Parse::Signature)?;
    if !trailing.is_empty() {
        return Err(Parse::Block(BlockError::TrailingData));
    }
    // Nested signatures are not decoded; they must still be DER.
    let mut whole = asn1::Reader::new(der, 0);
    whole
        .read(asn1::tag::SEQUENCE)
        .and_then(|tlv| asn1::validate(&tlv))
        .map_err(|e| Parse::Signature(e.into()))?;
    if sip.guid != style.sip_guid || sip.version != style.sip_version {
        return Err(Parse::Signature(SignatureError::SipMismatch));
    }
    Ok(signed)
}

/// Reads the script at `path` as `kind`, within [`ScriptOptions::max_size`]
/// (a larger file is not read), and checks its signature block.
pub fn verify_script_file(
    path: &Path,
    kind: ScriptKind,
    options: &ScriptOptions,
) -> std::io::Result<ScriptReport> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size > options.max_size {
        return Ok(ScriptReport {
            size,
            signing_state: ScriptSigningState::TooLargeForSignatureCheck {
                size,
                limit: options.max_size,
            },
            ..not_read(kind, options)
        });
    }
    // The file can grow after the size check: read at most one byte more
    // than the limit, so growth is reported rather than read.
    let mut data = Vec::new();
    file.take(options.max_size.saturating_add(1))
        .read_to_end(&mut data)?;
    Ok(verify_script(&data, kind, options))
}

/// Which trust anchors a script's chain may end in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptAnchorPolicy {
    /// The machine root store only, as the OS requires for scripts.
    OsRootStore,
    /// The policy's trust bundle only.
    PolicyAnchors,
    /// Either; the policy's bundle is tried first.
    #[default]
    Either,
}

/// The anchor sets a script's chain can be built against.
#[derive(Debug, Clone, Copy)]
pub struct ScriptTrustAnchors<'a> {
    /// The policy's trust bundle.
    pub policy: &'a TrustConfig,
    /// The machine root store, as a [`TrustConfig`] the caller reads from
    /// the OS (reading it is `os-trust`, #48). `None` when it is not
    /// available: [`ScriptAnchorPolicy::OsRootStore`] then trusts nothing.
    pub os_root_store: Option<&'a TrustConfig>,
}

/// The anchor set a trusted script chain ended in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScriptAnchorSource {
    /// The machine root store.
    OsRootStore,
    /// The policy's trust bundle.
    PolicyAnchors,
}

/// The trust verdict on a script's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptTrust {
    /// The policy applied.
    pub policy: ScriptAnchorPolicy,
    /// The anchor set the trusted chain ended in; `None` when the signer is
    /// not trusted under the policy.
    pub anchor: Option<ScriptAnchorSource>,
    /// The trust report under that anchor set (when no set trusts the
    /// signer, under the first set tried, for diagnostics). Its
    /// `identity` has no product name: scripts have no version resource.
    pub trust: TrustReport,
    /// The signed metadata of the trusted signature: the version and name
    /// fields of a script's identity, whose source is the signed metadata.
    /// `None` when the signer is not trusted.
    pub signed_metadata: Option<SignedMetadata>,
    /// `(publisher name, signed product)`, both present and the signer
    /// trusted: for publisher plus product rules (ISM-1471) on scripts.
    pub publisher_product: Option<(String, String)>,
}

/// Builds the chain of `report`'s signature against the anchor sets
/// `policy` allows, and decides whether its signer is trusted. Expiry,
/// timestamps and revocation are
/// [`crate::authenticode::evaluate_validity`], with
/// [`ScriptReport::signatures`] and [`ScriptTrust::trust`].
#[must_use]
pub fn evaluate_script_trust(
    report: &ScriptReport,
    anchors: &ScriptTrustAnchors<'_>,
    policy: ScriptAnchorPolicy,
) -> ScriptTrust {
    let empty = TrustConfig::new();
    let candidates: &[(ScriptAnchorSource, Option<&TrustConfig>)] = match policy {
        ScriptAnchorPolicy::OsRootStore => {
            &[(ScriptAnchorSource::OsRootStore, anchors.os_root_store)]
        }
        ScriptAnchorPolicy::PolicyAnchors => {
            &[(ScriptAnchorSource::PolicyAnchors, Some(anchors.policy))]
        }
        ScriptAnchorPolicy::Either => &[
            (ScriptAnchorSource::PolicyAnchors, Some(anchors.policy)),
            (ScriptAnchorSource::OsRootStore, anchors.os_root_store),
        ],
    };
    let mut first = None;
    for (source, config) in candidates {
        let trust = evaluate_trust(&report.signatures, config.unwrap_or(&empty), None);
        // Only a valid script signature can be trusted; `evaluate_trust`
        // already ignores invalid ones, and this keeps it so.
        let signed_metadata = trust
            .primary
            .filter(|_| report.signing_state == ScriptSigningState::Valid)
            .and_then(|p| report.signatures.signatures.get(p))
            .and_then(|s| s.signer.as_ref())
            .map(|a| a.signed_metadata.clone());
        if let Some(signed_metadata) = signed_metadata {
            let publisher_product = trust
                .identity
                .as_ref()
                .and_then(|i| i.publisher_name.as_ref())
                .zip(signed_metadata.product.as_ref())
                .map(|(p, product)| (p.value.clone(), product.clone()));
            return ScriptTrust {
                policy,
                anchor: Some(*source),
                trust,
                signed_metadata: Some(signed_metadata),
                publisher_product,
            };
        }
        first.get_or_insert(trust);
    }
    ScriptTrust {
        policy,
        anchor: None,
        trust: first.unwrap_or_else(|| evaluate_trust(&report.signatures, &empty, None)),
        signed_metadata: None,
        publisher_product: None,
    }
}
