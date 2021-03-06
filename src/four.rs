use common;
use common::EncodingError;
use std::cmp;
use three;

/// Challenge four: Find a single character XOR
///
/// # Arguments
/// * `path` The path to the file containing the strings
/// * `test_key` The byte key to test against
///
/// # Return
/// `true` if the discovered key matches the given `test_key`
pub fn challenge_four(path: &str, test_key: u8) -> bool {
    debug!("Looking for encrypted strings in {}", path);
    let matches = find_encrypted_string(path).expect("Could not find any matches");
    debug!("Found {} potential matches", matches.len(),);

    for cur in &matches {
        debug!(
            "Matched message: \"{}\"\n\tMessage used key: {}\n\tHemming distance {}",
            cur.msg, cur.key, cur.score
        );
    }

    if matches[0].key != test_key {
        return false;
    }
    debug!("Succesfully found encrypted string key!");

    true
}

/// Given a path to a text file, splits its content by `\n` and attempts to
/// bruteforce each string with all possible bytes value. English letters
/// occurence to find the best match.
///
/// # Arguments
/// * `path` The path to the input text file
///
/// # Return
/// A vector of `Decrypted` objects containing the details of each match. Sorted
/// by the number of trigrams in each.
pub fn find_encrypted_string(path: &str) -> Result<Vec<three::Decrypted>, EncodingError> {
    let file_content = common::get_file_contents(path)?;

    let lines = file_content.as_str().split('\n').collect::<Vec<&str>>();
    if file_content == "" || lines.is_empty() {
        return Err(EncodingError::new("Empty file contents"));
    }

    let mut out: Vec<three::Decrypted> = Vec::new();

    for line in lines {
        let line_hex = common::string_to_hex(line)?;
        let mut results = three::bruteforce(&line_hex, three::english_distance)?;

        out.append(&mut results);
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
