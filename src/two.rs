use common::EncodingError;

/// Simple XOR algorithm given a bytes array and a key of the same length to apply to each byte.
///
/// # Arguments
/// * `bytes` The byte array to XOR
/// * `key` a key of the same length as the `bytes` to apply to each character
///
/// # Returns
/// A vector of the XORed bytes. An `EncodingError` if we could not XOR.
pub fn xor_bytes(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if bytes.len() != key.len() {
        return Err(EncodingError::new(
            "Key length is different from bytes length",
        ));
    }
    let mut out: Vec<u8> = Vec::new();
    for (cnt, byte) in bytes.iter().enumerate() {
        let key_byte = key[cnt];

        // this could be a lot easier. However, we are not here to make our lives easier.
        // Instead we implement the XOR alogirthm manually working with individual bits
        // out.push(byte ^ key_byte);

        let char_bits = byte_to_bits(*byte);
        if char_bits.len() != 8 {
            return Err(EncodingError::new("Wrong bits in string byte"));
        }
        let key_bits = byte_to_bits(key_byte);
        if key_bits.len() != 8 {
            return Err(EncodingError::new("Wrong bits in key byte"));
        }

        let mut xor_bits: Vec<u8> = Vec::new();
        for (cnt, b) in char_bits.iter().enumerate() {
            if *b != key_bits[cnt] {
                xor_bits.push(1);
            } else {
                xor_bits.push(0);
            }
        }
        if xor_bits.len() != 8 {
            return Err(EncodingError::new(&format!(
                "Xor-ed bits have different length: {}",
                xor_bits.len()
            )));
        }
        out.push(bits_to_byte(xor_bits.as_slice()));
    }

    Ok(out)
}

/// Given a `u8` byte returns its bit represnetation as a `Vec`.
///
/// # Arguments
/// * `byte` A byte to be split
///
/// # Return
/// A `Vec` of bits from the original byte
fn byte_to_bits(byte: u8) -> Vec<u8> {
    (0u8..8).map(move |i| (byte >> i) & 1).collect::<Vec<u8>>()
}

/// Converts a `Vec` of bits into a byte.
///
/// # Arguments
/// * `bits` A `vec` of bits to be merged into a byte
///
/// # Return
/// The byte reprensetation of the given bits
fn bits_to_byte(bits: &[u8]) -> u8 {
    bits.iter().rev().fold(0, |acc, &b| (acc << 1) | b)
}
