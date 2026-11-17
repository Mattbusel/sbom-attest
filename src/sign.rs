//! ECDSA P-256 keys, detached signatures that `cosign verify-blob` accepts, DSSE
//! envelopes (in-toto attestations, `cosign verify-blob-attestation`), and JSF
//! signatures embedded in CycloneDX documents.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use serde_json::{json, Value};
use std::path::Path;

pub const DSSE_INTOTO: &str = "application/vnd.in-toto+json";

/// Generate a key pair: PKCS#8 private key PEM and SubjectPublicKeyInfo public key PEM.
pub fn keygen() -> Result<(String, String)> {
    let sk = SigningKey::random(&mut rand_core::OsRng);
    let private = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encoding private key: {e}"))?
        .to_string();
    let public = sk
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encoding public key: {e}"))?;
    Ok((private, public))
}

/// Load a private key: a path to a PEM file, or `env:VAR` holding the PEM.
pub fn load_signing_key(spec: &str) -> Result<SigningKey> {
    let pem = match spec.strip_prefix("env:") {
        Some(var) => std::env::var(var).with_context(|| format!("environment variable {var}"))?,
        None => std::fs::read_to_string(spec).with_context(|| format!("reading key {spec}"))?,
    };
    if pem.contains("ENCRYPTED") {
        bail!("encrypted keys are not supported; use an unencrypted PKCS#8 P-256 key (sbom-attest keygen)");
    }
    SigningKey::from_pkcs8_pem(&pem).map_err(|e| anyhow!("not a PKCS#8 P-256 private key: {e}"))
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    VerifyingKey::from_public_key_pem(&pem).map_err(|e| anyhow!("not a P-256 public key: {e}"))
}

pub fn public_pem(sk: &SigningKey) -> Result<String> {
    sk.verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow!("{e}"))
}

/// Key id: SHA-256 of the DER SubjectPublicKeyInfo.
pub fn key_id(vk: &VerifyingKey) -> String {
    let der = vk
        .to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .unwrap_or_default();
    crate::util::sha256(&der)
}

/// Detached signature over `data`: base64 of the DER ECDSA-SHA256 signature, the
/// format `cosign sign-blob` writes and `cosign verify-blob --signature` reads.
pub fn sign_blob(sk: &SigningKey, data: &[u8]) -> String {
    let sig: DerSignature = sk.sign(data);
    STANDARD.encode(sig.as_bytes())
}

pub fn verify_blob(vk: &VerifyingKey, data: &[u8], sig_b64: &str) -> Result<()> {
    let raw = STANDARD
        .decode(sig_b64.trim())
        .context("signature is not base64")?;
    let sig = Signature::from_der(&raw)
        .or_else(|_| Signature::from_slice(&raw))
        .map_err(|e| anyhow!("bad signature encoding: {e}"))?;
    vk.verify(data, &sig)
        .map_err(|_| anyhow!("signature does not verify"))
}

/// DSSE pre-authentication encoding.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    v.extend_from_slice(payload);
    v
}

/// Wrap a payload in a signed DSSE envelope.
pub fn dsse_sign(sk: &SigningKey, payload_type: &str, payload: &[u8]) -> Value {
    let sig: DerSignature = sk.sign(&pae(payload_type, payload));
    json!({
        "payloadType": payload_type,
        "payload": STANDARD.encode(payload),
        "signatures": [{
            "keyid": key_id(sk.verifying_key()),
            "sig": STANDARD.encode(sig.as_bytes()),
        }],
    })
}

/// Verify a DSSE envelope and return its payload.
pub fn dsse_verify(vk: &VerifyingKey, env: &Value) -> Result<Vec<u8>> {
    let ptype = env["payloadType"]
        .as_str()
        .ok_or_else(|| anyhow!("no payloadType"))?;
    let payload = STANDARD
        .decode(
            env["payload"]
                .as_str()
                .ok_or_else(|| anyhow!("no payload"))?,
        )
        .context("payload is not base64")?;
    let msg = pae(ptype, &payload);
    let sigs = env["signatures"]
        .as_array()
        .ok_or_else(|| anyhow!("no signatures"))?;
    for s in sigs {
        if let Some(b) = s["sig"].as_str() {
            if verify_blob(vk, &msg, b).is_ok() {
                return Ok(payload);
            }
        }
    }
    bail!("no DSSE signature verifies with this key")
}

/// RFC 8785 (JCS) canonical form. serde_json's default map is sorted by key and its
/// string escaping matches JCS for the integer-only documents written here.
pub fn canonical(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                // JCS orders by UTF-16 code units; identical to byte order for ASCII keys
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            // JCS writes numbers the way ECMAScript does: 1.0 is "1"
            Value::Number(n) if n.is_f64() => match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => {
                    Value::from(f as i64)
                }
                _ => v.clone(),
            },
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).unwrap_or_default()
}

fn jwk(vk: &VerifyingKey) -> Value {
    let point = vk.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().map(|x| &x[..]).unwrap_or_default()),
        "y": URL_SAFE_NO_PAD.encode(point.y().map(|y| &y[..]).unwrap_or_default()),
    })
}

/// Add a JSF (JSON Signature Format) ES256 signature to a CycloneDX document, in the
/// top-level `signature` property CycloneDX 1.6 defines.
pub fn jsf_sign(sk: &SigningKey, doc: &mut Value) {
    doc["signature"] = json!({ "algorithm": "ES256", "publicKey": jwk(sk.verifying_key()) });
    let sig: Signature = sk.sign(&canonical(doc));
    doc["signature"]["value"] = Value::String(URL_SAFE_NO_PAD.encode(sig.to_bytes()));
}

/// Verify the embedded JSF signature. Uses the embedded public key unless one is given,
/// and returns the key id that verified.
pub fn jsf_verify(doc: &Value, expected: Option<&VerifyingKey>) -> Result<String> {
    let s = doc
        .get("signature")
        .ok_or_else(|| anyhow!("document has no signature"))?;
    if s["algorithm"] != "ES256" {
        bail!("unsupported JSF algorithm {}", s["algorithm"]);
    }
    let value = s["value"]
        .as_str()
        .ok_or_else(|| anyhow!("signature has no value"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(value)
        .context("signature value is not base64url")?;
    let sig = Signature::from_slice(&raw).map_err(|e| anyhow!("{e}"))?;
    let embedded = {
        let k = &s["publicKey"];
        let x = URL_SAFE_NO_PAD
            .decode(k["x"].as_str().unwrap_or(""))
            .unwrap_or_default();
        let y = URL_SAFE_NO_PAD
            .decode(k["y"].as_str().unwrap_or(""))
            .unwrap_or_default();
        let mut sec1 = vec![4u8];
        sec1.extend(x);
        sec1.extend(y);
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| anyhow!("bad embedded key: {e}"))?
    };
    let vk = expected.unwrap_or(&embedded);
    if expected.is_some_and(|e| e != &embedded) {
        bail!("the document was signed with a different key");
    }
    let mut unsigned = doc.clone();
    if let Some(m) = unsigned["signature"].as_object_mut() {
        m.remove("value");
    }
    vk.verify(&canonical(&unsigned), &sig)
        .map_err(|_| anyhow!("JSF signature does not verify"))?;
    Ok(key_id(vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        let (private, _) = keygen().unwrap();
        SigningKey::from_pkcs8_pem(&private).unwrap()
    }

    #[test]
    fn blob_roundtrip_and_tamper() {
        let sk = key();
        let sig = sign_blob(&sk, b"hello");
        verify_blob(sk.verifying_key(), b"hello", &sig).unwrap();
        assert!(verify_blob(sk.verifying_key(), b"hellO", &sig).is_err());
    }

    #[test]
    fn dsse_roundtrip_and_tamper() {
        let sk = key();
        let env = dsse_sign(&sk, DSSE_INTOTO, br#"{"a":1}"#);
        assert_eq!(
            dsse_verify(sk.verifying_key(), &env).unwrap(),
            br#"{"a":1}"#
        );
        let mut bad = env.clone();
        bad["payload"] = Value::String(STANDARD.encode(br#"{"a":2}"#));
        assert!(dsse_verify(sk.verifying_key(), &bad).is_err());
    }

    #[test]
    fn pae_matches_spec_example() {
        // from the DSSE protocol document
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn jsf_roundtrip_and_tamper() {
        let sk = key();
        let mut doc =
            json!({"bomFormat": "CycloneDX", "components": [{"name": "a"}], "version": 1});
        jsf_sign(&sk, &mut doc);
        jsf_verify(&doc, None).unwrap();
        jsf_verify(&doc, Some(sk.verifying_key())).unwrap();
        let other = key();
        assert!(jsf_verify(&doc, Some(other.verifying_key())).is_err());
        doc["components"][0]["name"] = json!("b");
        assert!(jsf_verify(&doc, None).is_err());
    }

    #[test]
    fn canonical_sorts_keys() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":{"d":"\u0001","c":[2,1]}}"#).unwrap();
        assert_eq!(
            String::from_utf8(canonical(&v)).unwrap(),
            r#"{"a":{"c":[2,1],"d":"\u0001"},"b":1}"#
        );
    }
}
