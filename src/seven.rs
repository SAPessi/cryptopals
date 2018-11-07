use common;
use common::EncodingError;
use one;
use openssl::symm;

/// Executes challenge seven: Decrypt cipher with AES in ECB mode
///
/// # Arguments
/// * `path` The path to the file containing the base64-encoded cipher
/// * `key` The key used to encrypt the content
/// * `test_content_start` The first few characters to test the decrypted content against
///
/// # Return
/// `true` if the decrypted string starts with the given `test_content_start`
pub fn challenge_seven(path: &str, key: &str, test_content_start: &str) -> bool {
    let base64_content = common::get_file_contents(path).expect("Could not read input file");
    let bytes = one::base64_decode(base64_content.as_str()).expect("Could not decode content");
    let decrypted = decrypt(bytes.as_slice(), key.as_bytes()).expect("Could not decrypt content");

    decrypted.starts_with(test_content_start)
}

/// Uses AWS 128 bit ECB to decrypt a cipher
///
/// # Arguments
/// * `cipher` The encrypted cipher
/// * `key` The key used to encrypt the cipher
///
/// # Return
/// The byte slice representing the decripted cipher text
pub fn decrypt_bytes(cipher: &[u8], key: &[u8]) -> Result<Vec<u8>, EncodingError> {
    let c = symm::Cipher::aes_128_ecb();
    let out_vec = symm::decrypt(c, key, Option::default(), cipher)?;

    Ok(out_vec)
}

/// Uses AWS 128 bit ECB to decrypt a cipher
///
/// # Arguments
/// * `ciper` The encrypted cipher
/// * `key` The key used to encrypt the cipher
///
/// # Return
/// The `String` representation of the decrypted cipher
pub fn decrypt(cipher: &[u8], key: &[u8]) -> Result<String, EncodingError> {
    let out_vec = decrypt_bytes(cipher, key)?;
    let out_string = String::from_utf8(out_vec)?;

    Ok(out_string)
}
