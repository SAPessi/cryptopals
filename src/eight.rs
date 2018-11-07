use common;
use common::EncodingError;
use std::collections::HashMap;

/// Executes challenge eight: given a file with a list of hex string, detect one that was
/// encrypted using AES in ECB mode
///
/// # Arguments
/// * `path` The path to the file containing the list of hex strings
/// * `test_idx`: The index of the string encrypted with AES in ECB mode
///
/// # Return
/// `true` if the guessed index of the string in the input file matches the given `test_idx`
pub fn challenge_eight(path: &str, test_idx: usize) -> bool {
    let file_contents = common::get_file_contents(path).expect("Could not load input file");
    let mut repeated = 0;
    for (cnt, line) in file_contents.split('\n').enumerate() {
        let line_bytes = common::string_to_hex(line).expect("Could not convert hex to byte slice");
        let repetitions =
            count_block_repetitions(line_bytes.as_slice()).expect("Could not determine if ECB");
        if repetitions > 1 {
            repeated = cnt;
            debug!("Line {} repeats chunks {} times", line, repetitions);
        }
    }

    repeated == test_idx
}

/// Given a cipher encrypted with AES counts the number of times a 16 bytes
/// block is repeated in the cipher.
///
/// # Arguments
/// * `cipher` The cipher text
///
/// # Return
/// A result with the number of times a 16 bytes block was repeated.
pub fn count_block_repetitions(cipher: &[u8]) -> Result<u8, EncodingError> {
    let mut chunks_count: HashMap<&[u8], u8> = HashMap::new();
    for chunk in cipher.chunks(16) {
        let count = chunks_count.entry(&chunk).or_insert(0);
        *count += 1;
    }

    let mut max_repetitions: u8 = 0;
    for v in chunks_count.values() {
        if *v > max_repetitions {
            max_repetitions = *v;
        }
    }
    Ok(max_repetitions)
}
