//! JSON Canonicalization Scheme (RFC 8785) for `serde_json::Value`.
//!
//! Spec 2.0 receipts sign `JCS(statement)` inside a DSSE envelope, so any
//! conforming implementation (in-toto, Sigstore, a Python one-liner) derives
//! the same bytes. Rules applied: object members sorted by UTF-16 code units
//! of their keys, no insignificant whitespace, RFC 8785 §3.2.2.2 string
//! escaping (which `serde_json` already implements), integers verbatim.
//!
//! Floating-point numbers are rejected: no erebus statement carries one and
//! the RFC's ES6 number formatting is a large surface for zero benefit.

use std::fmt::Write;

use serde_json::Value;

/// Canonical bytes of `value`.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, anyhow::Error> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_value(value: &Value, out: &mut String) -> Result<(), anyhow::Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                anyhow::bail!("JCS: floating-point numbers are not supported in receipts");
            }
            write!(out, "{n}")?;
        }
        Value::String(s) => write_string(s, out)?,
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| utf16_units(k));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out)?;
                out.push(':');
                if let Some(v) = map.get(*key) {
                    write_value(v, out)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `serde_json` escapes exactly the RFC 8785 set: `"`, `\`, and controls
/// below 0x20 as `\b \t \n \f \r` or lowercase `\u00xx`.
fn write_string(s: &str, out: &mut String) -> Result<(), anyhow::Error> {
    let quoted = serde_json::to_string(s)?;
    out.push_str(&quoted);
    Ok(())
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: &Value) -> String {
        String::from_utf8(canonicalize(v).unwrap()).unwrap()
    }

    #[test]
    fn rfc_8785_sorting_vector() {
        // RFC 8785 §3.2.3 example: keys sorted by UTF-16 code units.
        let v: Value = serde_json::from_str(
            r#"{
              "\u20ac": "Euro Sign",
              "\r": "Carriage Return",
              "\ufb33": "Hebrew Letter Dalet With Dagesh",
              "1": "One",
              "\ud83d\ude00": "Emoji: Grinning Face",
              "\u0080": "Control",
              "\u00f6": "Latin Small Letter O With Diaeresis"
            }"#,
        )
        .unwrap();
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canon(&v), expected);
    }

    #[test]
    fn rfc_8785_literals_and_whitespace_vector() {
        let v: Value = serde_json::from_str(
            r#"{
              "literals": [null, true, false],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "numbers": [1, 0, -1, 10000000000]
            }"#,
        )
        .unwrap();
        assert_eq!(
            canon(&v),
            "{\"literals\":[null,true,false],\"numbers\":[1,0,-1,10000000000],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn nested_objects_are_sorted_recursively_and_floats_rejected() {
        let v = json!({"b": {"z": 1, "a": [{"y": 2, "x": 3}]}, "a": "s"});
        assert_eq!(canon(&v), r#"{"a":"s","b":{"a":[{"x":3,"y":2}],"z":1}}"#);
        assert!(canonicalize(&json!({"f": 1.5})).is_err());
    }

    #[test]
    fn canonical_form_is_a_fixpoint() {
        let v = json!({"k": ["v", {"n": null, "i": -7}], "a": "\u{1f600}"});
        let once = canonicalize(&v).unwrap();
        let reparsed: Value = serde_json::from_slice(&once).unwrap();
        assert_eq!(canonicalize(&reparsed).unwrap(), once);
    }
}
