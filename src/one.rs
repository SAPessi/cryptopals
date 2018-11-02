use std::error;
use std::fmt;

/// Max length of a line in a base64 encoded string
const B64_MAX_LINE_LENGTH: usize = 76;
/// Array of valid characters kn base64 in the correct order
static B64_CHARS: &'static [char; 64] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

/// Trait to extend the `String` type with a `push_b64` method. The method
/// simply taakes care of adding a newline in the string when the maximum
/// length is reached. The max length is define in the `B64_MAX_LINE_LENGTH`
/// constant.
pub trait Base64String {
    /// Appends a character to the String and adds a newline if necessary.
    fn push_b64(&mut self, c: char);
}

impl Base64String for String {
    fn push_b64(&mut self, c: char) {
        if !self.is_empty() && self.len() % B64_MAX_LINE_LENGTH == 0 {
            debug!("Adding newline to base64 string at length {}", self.len());
            self.push('\n');
        }

        self.push(c);
    }
}

/// Custom error type for the exercise methods. Used in all the functions to
/// return a `Result` type.
#[derive(Debug, Clone)]
pub struct EncodingError {
    message: String,
}

impl EncodingError {
    fn new(msg: &str) -> EncodingError {
        EncodingError {
            message: String::from(msg),
        }
    }
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for EncodingError {
    fn description(&self) -> &str {
        self.message.as_str()
    }

    fn cause(&self) -> Option<&error::Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

/// Converts a string to its hexadecimal representation.
///
/// # Arguments
/// * `string` The string to be converted
///
/// # Return
/// A result containing the `Vec<u8>` representation of the given
/// string. An `EncodingError` if the conversion fails.
pub fn string_to_hex(string: &str) -> Result<Vec<u8>, EncodingError> {
    let mut v = Vec::new();
    let mut cs = string.chars();
    debug!(
        "Converting string {} of length {} to hex",
        string,
        string.len()
    );
    loop {
        let pair = (cs.next(), cs.next());
        match pair {
            (Some(h), Some(l)) => {
                let h = char_to_hex(h)?;
                let l = char_to_hex(l)?;
                let byte = (h << 4) | l;
                v.push(byte);
            }
            (Some(_), None) => {
                error!("Odd number of characters in string");
                return Err(EncodingError::new(
                    "Odd number of characters in string, not valid hex",
                ));
            }
            _ => break,
        }
    }
    Ok(v)
}

/// Converts a char to its hexadecimal represnetation
///
/// # Arguments
/// * `c` The char to be converted
///
/// # Return
/// A `Result` with the `u8` value for the char, otherwise
/// an `EncodingError`
fn char_to_hex(c: char) -> Result<u8, EncodingError> {
    match c {
        '0'...'9' => Ok(c as u8 - b'0'),
        'a'...'f' => Ok(10 + (c as u8 - b'a')),
        _ => Err(EncodingError::new(
            "char_to_hex only converts char values between '0' and 'f'",
        )),
    }
}

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

/// Converts an array of bytes (hexadecimal) into its string representation
///
/// # Arguments
/// * `hex` The array of bytes to be converted.
///
/// # Return
/// The string represnetation of the vector (2 characters per byte). Otherwise
/// an `EncodingError`.
pub fn hex_to_string(hex: &[u8]) -> Result<String, EncodingError> {
    let mut out = String::from("");
    for byte in hex {
        let h = (byte & 0xF0) >> 4;
        let l = byte & 0x0F;
        let h_char = hex_to_char(h)?;
        let l_char = hex_to_char(l)?;

        out.push_str(&format!("{}{}", h_char, l_char));
    }

    Ok(out)
}

/// Converts a single short value (`u8`) into its char representation
///
/// # Arguments
/// * `short` The `u8` to be converted
///
/// # Return
/// The char representation of the give `u8`.
fn hex_to_char(short: u8) -> Result<char, EncodingError> {
    match short {
        0x0...0x9 => Ok((short + b'0') as char),
        0xa...0xf => Ok((short - 0xa + b'a') as char),
        _ => Err(EncodingError::new(
            "hex_to_char only converts short values between 0x0 and 0xf",
        )),
    }
}
