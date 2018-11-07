use openssl;
use std::error;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::string;

/// Max length of a line in a base64 encoded string
const B64_MAX_LINE_LENGTH: usize = 76;

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
    pub fn new(msg: &str) -> EncodingError {
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

/// Simple implementation of the `From` trait to generate an `EncodingError`
/// from an `std::io::Error`.
impl From<io::Error> for EncodingError {
    fn from(e: io::Error) -> Self {
        EncodingError::new(e.description())
    }
}

/// Creates an EncodingError from an OpenSSL error stack
impl From<openssl::error::ErrorStack> for EncodingError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        let mut desc = String::from(e.description());
        for err in e.errors() {
            let new_desc = format!(
                "{}\n{}-{}:{}",
                desc.clone(),
                err.library().unwrap_or(""),
                err.file(),
                err.line()
            );
            desc = new_desc;
        }
        EncodingError::new(desc.as_str())
    }
}

/// Creates an EncodingError from an OpenSSL error stack
impl From<string::FromUtf8Error> for EncodingError {
    fn from(e: string::FromUtf8Error) -> Self {
        EncodingError::new(e.description())
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

pub fn get_file_contents(path: &str) -> Result<String, EncodingError> {
    let file_path = Path::new(path);
    let mut strings_file = File::open(file_path)?;

    let mut file_content = String::from("");
    strings_file.read_to_string(&mut file_content)?;

    Ok(file_content)
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
