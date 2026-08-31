//! GGUF header + tensor manifest parsing.
//!
//! This module provides a parser for the GGUF model format (Ggml Universal
//! File) that records every tensor in a file as a [`TensorManifest`]. The
//! manifest is stored on [`crate::layer::ModelLayer`] at build time so a
//! later integrity check can re-parse the file and detect weight swapping:
//! replacing one tensor with another changes tensor offsets/names and is
//! caught by [`crate::layer::verify_tensor_manifest`].

use crate::layer::{TensorInfo, TensorManifest};
use std::io::{self, Cursor, Read};

/// GGUF magic constant: `"GGUF"` little-endian (u32 0x46554747).
const GGUF_MAGIC: u32 = 0x4655_4747;

/// Errors produced while parsing a GGUF header.
#[derive(Debug, thiserror::Error)]
pub enum GgufError {
    #[error("not a GGUF file (bad magic {0:#010x})")]
    BadMagic(u32),
    #[error("unsupported GGUF version {0}")]
    UnsupportedVersion(u32),
    #[error("truncated GGUF file")]
    Truncated,
    #[error("string length {0} exceeds remaining {1} bytes")]
    StringTooLong(u64, u64),
    #[error("tensor dims {0} exceed max of {1}")]
    TooManyDims(u32, u32),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Read a little-endian u32 from a reader, mapping EOF to [`GgufError::Truncated`].
fn read_u32(r: &mut impl Read) -> Result<u32, GgufError> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).map_err(map_eof)?;
    Ok(u32::from_le_bytes(b))
}

/// Read a little-endian u64 from a reader, mapping EOF to [`GgufError::Truncated`].
fn read_u64(r: &mut impl Read) -> Result<u64, GgufError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).map_err(map_eof)?;
    Ok(u64::from_le_bytes(b))
}

/// Convert an IO error, folding EOF into the structured `Truncated` variant.
fn map_eof(e: io::Error) -> GgufError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        GgufError::Truncated
    } else {
        GgufError::Io(e)
    }
}

/// Read a GGUF string: u64 length (big-endian byte label) then raw bytes.
fn read_string(r: &mut impl Read, remaining: u64) -> Result<(String, u64), GgufError> {
    let len = read_u64(r)?;
    if len > remaining {
        return Err(GgufError::StringTooLong(len, remaining));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).map_err(map_eof)?;
    // GGUF strings are byte strings; lossy conversion keeps names readable.
    Ok((String::from_utf8_lossy(&buf).into_owned(), len))
}

/// Skip one scalar-typed GGUF metadata value of the given `GGMLValueType`.
///
/// Fixed-width types skip their exact width; the `STRING` type carries a length
/// prefix followed by bytes. Array values are handled by the caller.
fn skip_scalar(c: &mut Cursor<&[u8]>, value_type: u32) -> Result<(), GgufError> {
    let width = match value_type {
        0 | 1 | 7 => 1, // uint8, int8, bool
        2 | 3 => 2,     // uint16, int16
        4..=6 => 4,     // uint32, int32, float32
        10..=12 => 8,   // uint64, int64, float64
        8 => {
            let (bytes, _) = read_string(c, remaining(c, 8))?;
            let _ = bytes;
            return Ok(());
        }
        9 => return Err(GgufError::Truncated), // array is handled by caller
        _ => return Err(GgufError::UnsupportedVersion(0xfeed_beef)),
    };
    let mut buf = vec![0u8; width];
    c.read_exact(&mut buf).map_err(map_eof)
}

/// Bytes left in the cursor's underlying slice.
fn remaining(c: &Cursor<&[u8]>, reserve: u64) -> u64 {
    let len = c.get_ref().len() as u64;
    len.saturating_sub(c.position().saturating_add(reserve))
}

/// Parse a GGUF header and all tensor info entries into a manifest.
///
/// Reads only the header + tensor metadata — it does NOT read the tensor
/// payload itself, so scanning a 4 GB model scans only tens of KB.
///
/// # Errors
///
/// Returns [`GgufError::BadMagic`] when `data` is not a GGUF file and
/// [`GgufError::Truncated`] when the header runs past the end of the buffer.
pub fn parse_header(data: &[u8]) -> Result<TensorManifest, GgufError> {
    let mut cursor = Cursor::new(data);
    let magic = read_u32(&mut cursor)?;
    if magic != GGUF_MAGIC {
        return Err(GgufError::BadMagic(magic));
    }
    let version = read_u32(&mut cursor)?;
    if version == 0 {
        return Err(GgufError::UnsupportedVersion(version));
    }
    let tensor_count = read_u64(&mut cursor)?;
    let kv_count = read_u64(&mut cursor)?;

    // Skip metadata key/value pairs. Each pair is: string key, u32 value-type
    // tag, then a type-specific encoded value. Types follow the GGUF
    // GGMLValueType enum (0..12); array values repeat [elem-type, count, ...].
    for _ in 0..kv_count {
        let rem = remaining(&cursor, 0);
        let _ = read_string(&mut cursor, rem)?;
        let value_type = read_u32(&mut cursor)?;
        if value_type == 9 {
            // ARRAY: element type u32, then u64 count.
            let elem_type = read_u32(&mut cursor)?;
            let count = read_u64(&mut cursor)?;
            for _ in 0..count {
                skip_scalar(&mut cursor, elem_type)?;
            }
        } else {
            skip_scalar(&mut cursor, value_type)?;
        }
    }

    let mut tensors = Vec::with_capacity(tensor_count.min(1 << 20) as usize);
    for _ in 0..tensor_count {
        let rem = remaining(&cursor, 0);
        let (name, _) = read_string(&mut cursor, rem)?;
        let n_dims = read_u32(&mut cursor)?;
        if n_dims > 8 {
            return Err(GgufError::TooManyDims(n_dims, 8));
        }
        let mut dims = Vec::with_capacity(n_dims as usize);
        for _ in 0..n_dims {
            let d = read_u64(&mut cursor)?;
            dims.push(d);
        }
        let ggml_type = read_u32(&mut cursor)?;
        let offset = read_u64(&mut cursor)?;
        tensors.push(TensorInfo {
            name,
            ggml_type: ggml_type_name(ggml_type),
            offset,
            dimensions: dims,
        });
    }

    Ok(TensorManifest {
        gguf_version: version,
        tensor_count,
        tensors,
    })
}

/// Map a GGML type enum value to its human-readable name.
#[must_use]
pub fn ggml_type_name(t: u32) -> String {
    let name = match t {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        6 => "Q5_0",
        7 => "Q5_1",
        8 => "Q8_0",
        9 => "Q8_1",
        10 => "Q2_K",
        11 => "Q3_K",
        12 => "Q4_K",
        13 => "Q5_K",
        14 => "Q6_K",
        15 => "Q8_K",
        16 => "IQ2_XXS",
        17 => "IQ2_XS",
        18 => "IQ3_XXS",
        19 => "IQ1_S",
        20 => "IQ4_NL",
        21 => "IQ3_XS",
        22 => "IQ2_S",
        23 => "IQ2_M",
        24 => "IQ4_XS",
        26 => "I32",
        27 => "I16",
        28 => "I8",
        29 => "I4",
        30 => "I2",
        31 => "BF16",
        32 => "TQ1_0",
        33 => "TQ2_0",
        other => return format!("UNKNOWN({other})"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::verify_tensor_manifest;

    /// Serialize a minimal GGUF header with one F16 tensor.
    fn build_gguf() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x4655_4747u32.to_le_bytes()); // magic
        v.extend_from_slice(&2u32.to_le_bytes()); // version
        v.extend_from_slice(&1u64.to_le_bytes()); // tensor count
        v.extend_from_slice(&0u64.to_le_bytes()); // kv count
                                                  // Tensor 0: name + dims + type + offset
        let name = b"tok_embeddings.weight";
        v.extend_from_slice(&(name.len() as u64).to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(&1u32.to_le_bytes()); // 1 dim
        v.extend_from_slice(&32000u64.to_le_bytes()); // dim=32000
        v.extend_from_slice(&1u32.to_le_bytes()); // type F16
        v.extend_from_slice(&123456u64.to_le_bytes()); // offset
        v
    }

    #[test]
    fn parses_valid_gguf() {
        let data = build_gguf();
        let m = parse_header(&data).unwrap();
        assert_eq!(m.gguf_version, 2);
        assert_eq!(m.tensor_count, 1);
        assert_eq!(m.tensors.len(), 1);
        assert_eq!(m.tensors[0].name, "tok_embeddings.weight");
        assert_eq!(m.tensors[0].ggml_type, "F16");
        assert_eq!(m.tensors[0].offset, 123456);
        assert_eq!(m.tensors[0].dimensions, vec![32000]);
    }

    #[test]
    fn rejects_non_gguf() {
        let err = parse_header(b"NOT A GGUF").unwrap_err();
        assert!(matches!(err, GgufError::BadMagic(_)));
    }

    #[test]
    fn rejects_truncated() {
        // Magic + version, then cut off.
        let mut v = Vec::new();
        v.extend_from_slice(&0x4655_4747u32.to_le_bytes());
        v.extend_from_slice(&2u32.to_le_bytes());
        let err = parse_header(&v).unwrap_err();
        assert!(matches!(err, GgufError::Truncated));
    }

    #[test]
    fn detects_weight_swap() {
        let original = build_gguf();
        let recorded = parse_header(&original).unwrap();
        // Attacker swaps weights: same count, but offset of tensor shifted.
        let mut swapped = original.clone();
        // Last 8 bytes are the offset; replace with a shifted offset.
        let offset = swapped.len() - 8;
        swapped[offset..].copy_from_slice(&999999u64.to_le_bytes());
        let parsed = parse_header(&swapped).unwrap();
        // The manifest comparison must reject the swap.
        assert!(!verify_tensor_manifest(&recorded, &parsed));
        // And the control case accepts it.
        let control = parse_header(&original).unwrap();
        assert!(verify_tensor_manifest(&recorded, &control));
    }

    #[test]
    fn ggml_type_names_known() {
        assert_eq!(ggml_type_name(0), "F32");
        assert_eq!(ggml_type_name(1), "F16");
        assert_eq!(ggml_type_name(12), "Q4_K");
        assert_eq!(ggml_type_name(0x7000_0000), "UNKNOWN(1879048192)");
    }
}
