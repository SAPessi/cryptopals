use common::EncodingError;
use openssl::symm;

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
