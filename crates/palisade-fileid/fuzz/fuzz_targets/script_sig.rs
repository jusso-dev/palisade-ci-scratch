//! Fuzzes script signature blocks (#52): text decoding, block scanning,
//! base64, the SignedData decoder, the digest and trust evaluation. The
//! first byte picks the format; the rest is the script. No input may
//! panic, and no state may claim more than the report backs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::authenticode::{SignatureKind, SignatureStatus, TrustConfig};
use palisade_fileid::script::{
    ScriptAnchorPolicy, ScriptKind, ScriptOptions, ScriptSigningState, ScriptTrustAnchors,
    evaluate_script_trust, verify_script,
};

const KINDS: [ScriptKind; 8] = [
    ScriptKind::PowerShell,
    ScriptKind::PowerShellXml,
    ScriptKind::Mof,
    ScriptKind::VbScript,
    ScriptKind::JScript,
    ScriptKind::WindowsScriptFile,
    ScriptKind::EncodedVbScript,
    ScriptKind::EncodedJScript,
];

fuzz_target!(|data: &[u8]| {
    let Some((first, script)) = data.split_first() else {
        return;
    };
    let kind = KINDS[usize::from(*first) % KINDS.len()];
    let report = verify_script(script, kind, &ScriptOptions::default());

    assert!(report.signatures.signatures.len() <= 1);
    if let Some(sig) = report.signature() {
        assert_eq!(sig.kind, SignatureKind::Script);
    }
    let valid = report.signing_state == ScriptSigningState::Valid;
    // Valid only with a valid signature over decodable text.
    assert_eq!(valid, report.signatures.primary.is_some());
    if valid {
        let sig = report.signature().unwrap();
        assert_eq!(sig.status, SignatureStatus::Valid);
        assert_eq!(sig.digest_match, Some(true));
        assert!(report.text_issue.is_none());
        assert!(report.block.is_some());
        assert!(!kind.is_encoded());
    }
    if report.signing_state == ScriptSigningState::DigestMismatch {
        assert_eq!(report.signature().unwrap().status, SignatureStatus::DigestMismatch);
    }
    if report.text_issue.is_some() {
        assert!(!valid);
        assert!(report.sip_digests.is_none());
        assert!(report.normalised_hash.is_none());
    }
    if let Some(block) = report.block {
        assert!(block.offset.saturating_add(block.len) <= report.size);
    }

    // Nothing is trusted with no anchors.
    let empty = TrustConfig::new();
    let anchors = ScriptTrustAnchors {
        policy: &empty,
        os_root_store: Some(&empty),
    };
    let trust = evaluate_script_trust(&report, &anchors, ScriptAnchorPolicy::Either);
    assert!(trust.anchor.is_none());
    assert!(trust.signed_metadata.is_none());
});
