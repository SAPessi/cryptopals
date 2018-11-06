use common::EncodingError;
use std::collections::HashMap;
use std::i32;
use std::u8;
use three;
use two;

/// Structure that represents a possible key length and the bit distance
/// between the blocks analyzed for the key
pub struct KeySize {
    /// The distance between the various blocks analyzed
    pub blocks_distance: f32,
    /// The length of the key with this distance
    pub key_length: u8,
}

/// Computes the bit (hemming) distance between two strings
///
/// # Arguments
/// * `first` The first string
/// * `second` The second string
///
/// # Return
/// The number of different bits between the two string
pub fn string_distance(first: &str, second: &str) -> i32 {
    bytes_distance(first.as_bytes(), second.as_bytes())
}

/// Computes the bit distance (hemming) between two byte slices.
///
/// # Arguments
/// * `first_bytes` The first slice
/// * `second_bytes` The second slices
///
/// # Return
/// The number of different bits between the two slices
fn bytes_distance(first_bytes: &[u8], second_bytes: &[u8]) -> i32 {
    let mut out: i32 = 0;
    let mut second_iter = second_bytes.iter();
    for byte in first_bytes {
        let first_bits = two::byte_to_bits(*byte);
        match second_iter.next() {
            Some(second_byte) => {
                let second_bits = two::byte_to_bits(*second_byte);
                for cnt in 0..8 {
                    if first_bits[cnt] != second_bits[cnt] {
                        out += 1;
                    }
                }
            }
            None => {
                out += first_bits.len() as i32;
            }
        }
    }

    out
}

/// Find the best key sizes given an encrypted input
///
/// # Argument
/// * `min_size` The minimum key to test against
/// * `max_size` The maximum size to test against
/// * `input` The byte slice to test keys against
///
/// # Return
/// A list of the best match keys
pub fn find_key_len(
    min_size: u8,
    max_size: u8,
    input: &[u8],
) -> Result<Vec<KeySize>, EncodingError> {
    if i32::from(max_size * 2) > input.len() as i32 {
        return Err(EncodingError::new(&format!(
            "The max size of the key ({}) is too long for the given input ({})",
            max_size,
            input.len()
        )));
    }

    // only take the min distance for each key len
    let mut mins: HashMap<u8, f32> = HashMap::new();

    for key_len in min_size..max_size {
        /*let mut first_bytes: Vec<u8> = vec!(key_len);
        let mut second_bytes: Vec<u8> = vec!(key_len);
        first_bytes.extend_from_slice(&input[0..key_len as usize]);
        second_bytes.extend_from_slice(&input[key_len as usize..(key_len*2) as usize]);*/
        let mut chunks = input.chunks(key_len as usize);
        let mut total_diff = 0.0;
        let mut pairs = 0;

        while let (Some(a), Some(b)) = (chunks.next(), chunks.next()) {
            pairs += 1;
            total_diff += bytes_distance(a, b) as f32;
        }

        let distance = (total_diff / pairs as f32) / f32::from(key_len);
        let entry_distance = mins.entry(key_len).or_insert(distance);
        if distance < *entry_distance {
            *entry_distance = distance;
        }
    }

    let mut out: Vec<KeySize> = Vec::new();
    for (k, v) in mins {
        out.push(KeySize {
            blocks_distance: v,
            key_length: k,
        });
    }

    Ok(out)
}

/// Transposes the given input into blocks containining the nth letter of each
/// chunk of the input. For example, "hello, world!" with a block size of 3
/// is first split into "hel", "lo,", " wo", "rld", "!". This, in turn, would
/// be transposed into:
///  - hl r!
///  - eowll
///  - lmod
///
/// # Argument
/// * `input` The input string to be transposed
/// * `block_size` The number of blocks to generate
///
/// # Return
/// The transposed input in the given number of blocks.
pub fn transpose_input(input: &[u8], block_size: u8) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    let chunks = input.chunks(block_size as usize);
    for chunk in chunks {
        for (i, b) in chunk.iter().enumerate() {
            if blocks.len() <= i {
                blocks.push(vec![*b]);
            } else if let Some(block) = blocks.get_mut(i) {
                block.push(*b)
            }
        }
    }

    blocks
}

/// Attempts to brute force each block in the given input with a single byte key.
///
/// # Arguments
/// * `blocks` The blocks to bruteforce
///
/// # Return
/// A vector where each byte is the most likely key for each one of the given
/// input blocks.
pub fn find_key(blocks: Vec<Vec<u8>>) -> Result<Vec<u8>, EncodingError> {
    let mut out: Vec<u8> = Vec::new();
    for block in blocks {
        let matches = three::bruteforce(block.as_slice(), three::english_distance)?;
        if matches.is_empty() {
            return Err(EncodingError::new(&format!(
                "Could not find a potential key for {}",
                String::from_utf8(block).unwrap_or_else(|_| "".to_string())
            )));
        }
        out.push(matches[0].key);
    }

    Ok(out)
}
