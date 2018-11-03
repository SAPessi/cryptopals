use common::EncodingError;
use std::cmp;
use two;

/// Most common trigrams from wikipedia: https://en.wikipedia.org/wiki/Trigram
static TRIGRAMS: &[&str; 16] = &[
    "the", "and", "tha", "ent", "ing", "ion", "tio", "for", "nde", "has", "nce", "edt", "tis",
    "oft", "sth", "men",
];

/// Struct to represent a potential match from the bruteforce algorithm
pub struct Decrypted {
    /// The decrypted message
    pub msg: String,
    /// The number of trigrams detected in the message
    pub trigrams: u8,
    /// The XOR key used for this decryption
    pub key: u8,
}

/// Attempts to decrypt a message using all possible values of a single byte
///
/// # Arguments
/// * `hex` The encrypted message bytes
/// * `min_trigrams` The minimum number of trigrams detected for a message to be considered valid
/// * `first_match` Whether to return at the first match or attempt all combinations
///
/// # Return
/// A `Result` containing a list of possible matches sorted by the number of trigrams
/// found in each. An `EncodingError` otherwise.
pub fn bruteforce(
    hex: &[u8],
    min_trigrams: u8,
    first_match: bool,
) -> Result<Vec<Decrypted>, EncodingError> {
    let mut out: Vec<Decrypted> = Vec::new();
    // loop over all possible values for a byte
    for key_char in 0x00..0xff {
        // reuse the function from challenge 2 so we generate a slice
        // with all bytes set to the same key
        let key: Vec<u8> = vec![key_char as u8; hex.len()];
        let decrypted_hex = two::xor_bytes(hex, key.as_slice())?;

        let out_string = String::from_utf8(decrypted_hex).unwrap_or_else(|_| "".to_string());
        if out_string == "" {
            continue;
        }
        let trigrams = count_trigrams(&out_string);

        // TODO: Must contain at least one space. Not sure this is a good rule.
        if trigrams >= min_trigrams && out_string.contains(' ') {
            out.push(Decrypted {
                msg: out_string,
                trigrams,
                key: key_char,
            });
            if first_match {
                return Ok(out);
            }
        }
    }

    out.sort_by(|a, b| {
        if a.trigrams > b.trigrams {
            return cmp::Ordering::Less;
        } else if a.trigrams < b.trigrams {
            return cmp::Ordering::Greater;
        }
        cmp::Ordering::Equal
    });

    Ok(out)
}

/// Counts the number of trigrams in the given string.
///
/// # Arguments
/// * `input` the String to check
///
/// # Return
/// The number of trigrams detected in the string
fn count_trigrams(input: &str) -> u8 {
    let mut cnt = 0;
    let input_without_spaces = input.replace(" ", "");
    for idx in 0..input_without_spaces.len() {
        let first = idx;
        let mut last = idx + 3;
        if last > input_without_spaces.len() {
            break;
        }

        let trigram: String = input_without_spaces.chars().skip(first).take(3).collect();
        if TRIGRAMS.contains(&trigram.to_lowercase().as_str()) {
            cnt += 1;
        }
    }
    cnt
}
