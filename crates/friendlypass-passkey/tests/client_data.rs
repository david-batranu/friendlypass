//! clientDataJSON shape and field order.

use friendlypass_passkey::{b64url_encode, client_data_json};

fn positions(json: &str, fields: &[&str]) -> Vec<usize> {
    fields
        .iter()
        .map(|field| {
            json.find(&format!("\"{field}\":"))
                .unwrap_or_else(|| panic!("missing {field}"))
        })
        .collect()
}

#[test]
fn field_order_is_type_challenge_origin_crossorigin() {
    let challenge = [0xa5u8; 32];
    let json = client_data_json("webauthn.create", &challenge, "https://example.com", None);
    assert_eq!(
        json,
        format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://example.com\",\"crossOrigin\":false}}",
            b64url_encode(&challenge)
        )
    );

    let order = positions(&json, &["type", "challenge", "origin", "crossOrigin"]);
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "fields must appear in WebAuthn serialization order: {order:?}"
    );
}

#[test]
fn android_package_name_is_appended_last() {
    let json = client_data_json(
        "webauthn.get",
        b"challenge",
        "android:apk-key-hash:abcdef",
        Some("org.friendlypass.android"),
    );
    assert_eq!(
        json,
        concat!(
            "{\"type\":\"webauthn.get\",",
            "\"challenge\":\"Y2hhbGxlbmdl\",",
            "\"origin\":\"android:apk-key-hash:abcdef\",",
            "\"crossOrigin\":false,",
            "\"androidPackageName\":\"org.friendlypass.android\"}"
        )
    );

    let order = positions(
        &json,
        &[
            "type",
            "challenge",
            "origin",
            "crossOrigin",
            "androidPackageName",
        ],
    );
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn challenge_is_encoded_base64url_without_padding() {
    // 2 bytes -> 3 base64 chars, no '='.
    let json = client_data_json("webauthn.get", &[0xfb, 0xff], "https://example.com", None);
    assert!(json.contains("\"challenge\":\"-_8\""), "{json}");
}

#[test]
fn values_are_json_escaped() {
    let json = client_data_json(
        "webauthn.get",
        b"",
        "https://example.com/\"quote\"\\path",
        Some("pkg\nname"),
    );
    assert!(json.contains(r#""origin":"https://example.com/\"quote\"\\path""#));
    assert!(json.contains(r#""androidPackageName":"pkg\nname""#));
    assert_eq!(json.matches('{').count(), 1);
}
