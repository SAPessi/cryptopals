use common::{Base64String, EncodingError};

/// Array of valid characters kn base64 in the correct order
static B64_CHARS: &'static [char; 64] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

/// Naive base64 encoding implementation. Encodes a byte vector into a base64 string
///
/// # Arguments
/// * `bytes` The vector to be encoded
///
/// # Return
/// The base64 encoded string representation of the vector. Otherwise
/// an `EncodingError`
pub fn base64_encode(bytes: Vec<u8>) -> Result<String, EncodingError> {
    debug!("Base64 encoding {} bytes", bytes.len());
    let mut out_str = String::from("");
    let mut bytes_iter = bytes.into_iter();
    loop {
        let next_bytes = (bytes_iter.next(), bytes_iter.next(), bytes_iter.next());
        match next_bytes {
            (Some(b1), Some(b2), Some(b3)) => {
                // generate 4, 6-bit numbers
                let c0 = b1 >> 2;
                let c1 = ((b1 & 0x3) << 4) | (b2 >> 4);
                let c2 = ((b2 & 0xf) << 2) | (b3 >> 6);
                let c3 = b3 & 0x3f;

                out_str.push_b64(B64_CHARS[c0 as usize]);
                out_str.push_b64(B64_CHARS[c1 as usize]);
                out_str.push_b64(B64_CHARS[c2 as usize]);
                out_str.push_b64(B64_CHARS[c3 as usize]);
            }
            (Some(b1), Some(b2), None) => {
                // generate 4, 6-bit numbers
                let c0 = b1 >> 2;
                let c1 = ((b1 & 0x3) << 4) | (b2 >> 4);
                let c2 = (b2 & 0xf) << 2;

                out_str.push_b64(B64_CHARS[c0 as usize]);
                out_str.push_b64(B64_CHARS[c1 as usize]);
                out_str.push_b64(B64_CHARS[c2 as usize]);
                out_str.push_b64('=');
            }
            (Some(b1), None, None) => {
                // generate 4, 6-bit numbers
                let c0 = b1 >> 2;
                let c1 = (b1 & 0x3) << 4;

                out_str.push_b64(B64_CHARS[c0 as usize]);
                out_str.push_b64(B64_CHARS[c1 as usize]);
                out_str.push_b64('=');
                out_str.push_b64('=');
            }
            _ => break,
        }
    }
    debug!("Generated string of len {}", out_str.len());
    Ok(out_str)
}

/// Naive base64 decoding implementation. Decodes a base64 encoded string
/// into its original byte vector
///
/// # Arguments
/// * `string` The base64 encoded string to be decoded
///
/// # Return
/// The original byte vector. Otherwise an `EncodingError`
pub fn base64_decode(string: &str) -> Result<Vec<u8>, EncodingError> {
    debug!("Base64 decode string {} of len {}", string, string.len());
    let sanitized_string = string.replace("\n", "");
    let mut iter = sanitized_string.chars();
    let mut out: Vec<u8> = Vec::new();
    loop {
        // we consider 4 bytes at a time
        let next_bytes = (iter.next(), iter.next(), iter.next(), iter.next());
        match next_bytes {
            (Some(b1), Some(b2), Some(b3), Some(b4)) => {
                let pos1 = get_char_position(b1)?;
                let pos2 = get_char_position(b2)?;
                let pos3 = get_char_position(b3)?;
                let pos4 = get_char_position(b4)?;

                let mut h = pos1 << 2;
                let mut m = pos2;
                let mut l: u8;
                h |= m >> 4;
                m <<= 4;
                out.push(h);
                m |= pos3 >> 2;
                l = pos3 << 6;
                out.push(m);
                l |= pos4;
                out.push(l);
            }
            _ => break,
        }
    }
    debug!("Generated {} bytes from string", out.len());
    Ok(out)
}

/// Return the position of a char in the array of valid base64
/// characters.
///
/// # Arguments
/// * `c` The char to look up
///
/// # Return
/// The position of the character in the base64 chars array. An
/// `EncodingError` if the character could not be found.
fn get_char_position(c: char) -> Result<u8, EncodingError> {
    if c == '=' {
        return Ok(b'0');
    }
    for (cnt, cur) in B64_CHARS.iter().enumerate() {
        if cur == &c {
            return Ok(cnt as u8);
        }
    }
    Err(EncodingError::new(&format!(
        "{} is not a valid base64 character",
        c
    )))
}
