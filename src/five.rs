use common;
use two;

/// Executes challenge five: Implement repeating-key XOR.
///
/// # Arguments
/// * `input` The input string to be XOR-ed
/// * `key` The key to XOR against
/// * `test_string` The expected XOR-ed output to test against
///
/// # Return
/// `true` if the XOR-ed string matched the given `test_string` and the reverse
/// XOR also matches the `input` parameter.
pub fn challenge_five(input: &str, key: &str, test_string: &str) -> bool {
    debug!("Encrypting string with repeating key XOR");
    let line_string = String::from(input);
    let input_bytes = line_string.as_bytes();
    debug!("Input bytes len: {}", input_bytes.len());
    let key_string = String::from(key);
    let key_bytes = key_string.as_bytes();
    debug!("Original key of length: {}", key_bytes.len());
    let extended_key = repeat_key(input_bytes.len(), key_bytes);
    debug!("Generated repeating key of length: {}", extended_key.len());
    let encrypted_bytes =
        two::xor_bytes(input_bytes, extended_key.as_slice()).expect("Could not encrypt input");

    let encrypted_hex =
        common::hex_to_string(encrypted_bytes.as_slice()).expect("Could not convert hex to string");

    if encrypted_hex != test_string.replace('\n', "") {
        error!(
            "Encrypted line: \"{}\" does not match \"{}\"",
            encrypted_hex, test_string
        );
        return false;
    }

    // decrypt and compare with original input
    let encrypted_bytes =
        common::string_to_hex(encrypted_hex.as_str()).expect("Could not turn hex to bytes");
    let decrypted_bytes = two::xor_bytes(encrypted_bytes.as_slice(), extended_key.as_slice())
        .expect("Could not decrypt input");
    let decrypted_string = String::from_utf8(decrypted_bytes)
        .expect("Could not turn decrypted bytes into UTF-8 string");
    if decrypted_string != input {
        error!(
            "Decrypted line: \"{}\" is different from original input \"{}\"",
            decrypted_string, input
        );
        return false;
    }
    true
}

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
