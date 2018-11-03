use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use common;
use common::EncodingError;
use three;

/// Simple implementation of the `From` trait to generate an `EncodingError`
/// from an `std::io::Error`.
impl From<io::Error> for EncodingError {
    fn from(e: io::Error) -> Self {
        EncodingError::new(e.description())
    }
}

/// Given a path to a text file, splits its content by `\n` and attempts to
/// bruteforce each string with all possible bytes value. Uses trigrams count
/// to determine whether the returned string is english.
///
/// # Arguments
/// * `path` The path to the input text file
/// * `min_trigrams` The minimum number of trigrams for a match to be considered
///   succesful
///
/// # Return
/// A vector of `Decrypted` objects containing the details of each match. Sorted
/// by the number of trigrams in each.
pub fn find_encrypted_string(
    path: &str,
    min_trigrams: u8,
) -> Result<Vec<three::Decrypted>, EncodingError> {
    let file_path = Path::new(path);
    let mut strings_file = File::open(file_path)?;

    let mut file_content = String::from("");
    strings_file.read_to_string(&mut file_content)?;
    let lines = file_content.as_str().split('\n').collect::<Vec<&str>>();
    if file_content == "" || lines.is_empty() {
        return Err(EncodingError::new("Empty file contents"));
    }

    let mut out: Vec<three::Decrypted> = Vec::new();

    for line in lines {
        let line_hex = common::string_to_hex(line)?;
        let mut results = three::bruteforce(&line_hex, min_trigrams, false)?;
        out.append(&mut results);
    }

    Ok(out)
}
