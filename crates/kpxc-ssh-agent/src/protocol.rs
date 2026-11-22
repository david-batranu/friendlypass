//! ssh-agent wire protocol (draft-miller-ssh-agent) message encoding.
//!
//! All integers are big-endian; messages are length-prefixed. Implemented
//! subset: `RequestIdentities` / `IdentitiesAnswer` and `SignRequest` /
//! `SignResponse` / failure.

use anyhow::{bail, Result};

use crate::openssh::{put_string, SshIdentity};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENT_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_SIGN_REQUEST: u8 = 13;

/// Encode a full agent message (with its u32 length prefix).
pub fn encode_message(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// An incoming agent request.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentRequest {
    RequestIdentities,
    SignRequest { keyblob: Vec<u8>, data: Vec<u8>, flags: u32 },
    Unsupported(u8),
}

/// Parse one agent request body (without the length prefix).
pub fn parse_request(body: &[u8]) -> Result<AgentRequest> {
    let Some(&type_byte) = body.first() else {
        bail!("empty agent request");
    };
    let rest = &body[1..];
    match type_byte {
        SSH_AGENT_REQUEST_IDENTITIES => Ok(AgentRequest::RequestIdentities),
        SSH_AGENT_SIGN_REQUEST => {
            let mut r = crate::openssh::BlobReader::new(rest);
            let keyblob = r.read_string()?.to_vec();
            let data = r.read_string()?.to_vec();
            let flags = r.read_u32()?;
            Ok(AgentRequest::SignRequest { keyblob, data, flags })
        }
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

/// Encode an `IdentitiesAnswer` for the given identities.
pub fn encode_identities_answer(identities: &[SshIdentity]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(SSH_AGENT_IDENTITIES_ANSWER);
    body.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for identity in identities {
        put_string(&mut body, &identity.public_blob());
        put_string(&mut body, identity.comment.as_bytes());
    }
    encode_message(&body)
}

/// Encode a `SignResponse` with an SSH-format signature blob.
pub fn encode_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(SSH_AGENT_SIGN_RESPONSE);
    put_string(&mut body, signature);
    encode_message(&body)
}

/// Encode a bare `SSH_AGENT_FAILURE`.
pub fn encode_failure() -> Vec<u8> {
    encode_message(&[SSH_AGENT_FAILURE])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssh::SshIdentity;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_identity() -> SshIdentity {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        SshIdentity {
            seed: [3u8; 32],
            public: signing.verifying_key().as_bytes().to_owned(),
            comment: "id_ed25519".into(),
        }
    }

    #[test]
    fn identities_answer_roundtrip_shape() {
        let answer = encode_identities_answer(&[test_identity()]);
        // message length prefix
        let len = u32::from_be_bytes(answer[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, answer.len() - 4);
        assert_eq!(answer[4], SSH_AGENT_IDENTITIES_ANSWER);
        let mut r = crate::openssh::BlobReader::new(&answer[5..]);
        assert_eq!(r.read_u32().unwrap(), 1);
        let blob = r.read_string().unwrap();
        let (public, _) = crate::openssh::parse_public_blob(blob).unwrap();
        assert_eq!(public, test_identity().public);
        assert_eq!(r.read_string().unwrap(), b"id_ed25519");
    }

    #[test]
    fn sign_request_parse_and_response_roundtrip() {
        let mut body = vec![SSH_AGENT_SIGN_REQUEST];
        let identity = test_identity();
        put_string(&mut body, &identity.public_blob());
        put_string(&mut body, b"authenticate me");
        body.extend_from_slice(&0_u32.to_be_bytes()); // flags

        let req = parse_request(&body).unwrap();
        match req {
            AgentRequest::SignRequest { keyblob, data, flags } => {
                assert_eq!(keyblob, identity.public_blob());
                assert_eq!(data, b"authenticate me");
                assert_eq!(flags, 0);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let sig = encode_sign_response(&identity.sign(b"authenticate me"));
        let len = u32::from_be_bytes(sig[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, sig.len() - 4);
        assert_eq!(sig[4], SSH_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn request_identities_parse() {
        let req = parse_request(&[SSH_AGENT_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(req, AgentRequest::RequestIdentities);
    }

    #[test]
    fn unsupported_type() {
        assert_eq!(parse_request(&[99]).unwrap(), AgentRequest::Unsupported(99));
    }
}
