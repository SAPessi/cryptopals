use common::EncodingError;
use std::cmp;
use std::collections::HashMap;
use two;

/// Most common trigrams from wikipedia: https://en.wikipedia.org/wiki/Trigram
static TRIGRAMS: &[&str; 16] = &[
    "the", "and", "tha", "ent", "ing", "ion", "tio", "for", "nde", "has", "nce", "edt", "tis",
    "oft", "sth", "men",
];

/// Struct to represent a potential match from the bruteforce algorithm
#[derive(Clone)]
pub struct Decrypted {
    /// The decrypted message
    pub msg: String,
    /// The number of trigrams detected in the message
    pub score: f32,
    /// The XOR key used for this decryption
    pub key: u8,
}

type BruteforceValidator = fn(&str) -> f32;

/// Attempts to decrypt a message using all possible values of a single byte
///
/// # Arguments
/// * `hex` The encrypted message bytes
/// * `validator` A function that assings a score to the given match. This module
///   includes a hemming and trigrams count implementation
///
/// # Return
/// A `Result` containing a list of possible matches sorted by the number of trigrams
/// found in each. An `EncodingError` otherwise.
pub fn bruteforce(
    hex: &[u8],
    validator: BruteforceValidator,
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
        let validator_score = validator(&out_string);

        out.push(Decrypted {
            msg: out_string,
            score: validator_score,
            key: key_char,
        });
    }

    out.sort_by(|a, b| {
        if a.score > b.score {
            return cmp::Ordering::Greater;
        } else if a.score < b.score {
            return cmp::Ordering::Less;
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
pub fn count_trigrams(input: &str) -> f32 {
    let mut cnt = 0;
    let input_without_spaces = input.replace(" ", "");
    for idx in 0..input_without_spaces.len() {
        if idx + 3 > input_without_spaces.len() {
            break;
        }

        let trigram: String = input_without_spaces.chars().skip(idx).take(3).collect();
        if TRIGRAMS.contains(&trigram.to_lowercase().as_str()) {
            cnt += 1;
        }
    }
    cnt as f32
}

/// Compares the occurrence of characters in the given string against the average occurrence
/// in the english langauge
///
/// # Arguments
/// * `input` The string to compare
///
/// # Return
/// The absolute sum of the difference in the occurrence of each char in the given
/// string vs the english language.
pub fn english_distance(input: &str) -> f32 {
    let english_count: HashMap<char, usize> = vec![
        (' ', 12802),
        ('e', 12702),
        ('t', 9056),
        ('a', 8167),
        ('o', 7507),
        ('i', 6966),
        ('n', 6749),
        ('s', 6327),
        ('h', 6094),
        ('r', 5987),
        ('d', 4253),
        ('l', 4025),
        ('c', 2782),
        ('u', 2758),
        ('m', 2406),
        ('w', 2361),
        ('f', 2228),
        ('g', 2015),
        ('y', 1974),
        ('p', 1929),
        ('b', 1492),
        ('v', 978),
        ('k', 772),
        ('j', 153),
        ('x', 150),
        ('q', 95),
        ('z', 74),
    ].into_iter()
    .collect();
    let english_total: f32 = 100_000.0;

    let mut input_count: HashMap<char, usize> = HashMap::new();
    let mut input_total: f32 = 0.0;
    for c in input.chars() {
        let c = c.to_lowercase().next().unwrap();
        let count = input_count.entry(c).or_insert(0);
        *count += 1;
        input_total += 1.0;
    }

    let mut diff = 0.0;
    for (k, v) in &input_count {
        let i = *v as f32 / input_total;
        let e = *english_count.get(k).unwrap_or(&0) as f32 / english_total;
        diff += (i - e).abs();
    }

    for k in english_count.keys() {
        if !input_count.contains_key(k) {
            let e = english_count[k] as f32 / english_total;
            diff += e;
        }
    }
    diff
}
