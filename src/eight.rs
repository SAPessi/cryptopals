use common::EncodingError;
use std::collections::HashMap;

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