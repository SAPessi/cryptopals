/// Given the length of the desired output and an original key as a byte slice
/// generates a `Vec<u8>` of the desired length populated with the key bytes
/// repeated in sequence. This function is used to generate keys for a
/// repeating-key XOR algorithm.
///
/// # Arguments
/// * `len` The desired output key length
/// * `key` The original key bytes
///
/// # Return
/// A generated key that repeats the give key bytes for the desired length.
pub fn repeat_key(len: usize, key: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for cnt in 0..len {
        let next_byte = key[(cnt as u8 % key.len() as u8) as usize];
        out.push(next_byte);
    }

    out
}
