#[macro_use]
extern crate log;
extern crate colored;
extern crate elapsed;
extern crate simple_logger;

pub mod common;
pub mod five;
pub mod four;
pub mod one;
pub mod three;
pub mod two;

use colored::*;
use elapsed::measure_time;

fn main() {
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    start_challenge("one", || {
        challenge_one(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )
    });

    start_challenge("two", || {
        challenge_two(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
            "746865206b696420646f6e277420706c6179",
        )
    });

    start_challenge("three", || {
        challenge_three(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            1,
        )
    });

    start_challenge("four", || challenge_four("./resources/four.txt", 3));

    start_challenge("five", || {
        challenge_five(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\na282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
    })
}

fn start_challenge<F: FnOnce() -> bool>(name: &str, f: F) {
    println!("{} {}", "Starting test".blue(), name.blue().bold());
    let (elapsed, test_output) = measure_time(f);
    if test_output {
        println!(
            "{} {} {} {}",
            "Executed test".green(),
            name.green().bold(),
            "succesfully in".green(),
            format!("{}", elapsed).green().bold()
        );
    } else {
        println!("{} {}", "Failed to execute test".red(), name.red().bold());
    }
}

fn challenge_one(hex: &str, test_string: &str) -> bool {
    debug!("Starting exercise one - base64 encoding");
    debug!("Encoding hex String: {}", hex);
    let hex_string = common::string_to_hex(hex).expect("Could not convert string");
    let hex_len = hex_string.len();
    let output = one::base64_encode(hex_string).expect("Could not base64 encode");
    debug!("Generaged encoded string: {}", output,);
    if output.as_str() != test_string {
        return false;
    }
    debug!("Succesfully encoded string!");

    debug!("Attempting to decode string again");
    let decoded_vec = one::base64_decode(&output).expect("Could not decode");
    debug!(
        "Decoded len: {}. Original len: {}",
        decoded_vec.len(),
        hex_len
    );
    let decoded_string =
        common::hex_to_string(decoded_vec.as_slice()).expect("Could not turn vector to string");
    debug!("Decoded string: {}", decoded_string);
    if hex != decoded_string {
        return false;
    }
    debug!("Succesfully decoded string!");

    true
}

fn challenge_two(hex: &str, key: &str, test_string: &str) -> bool {
    debug!("XORing {} with key: {}", hex, key);
    let hex_vec = common::string_to_hex(hex).expect("Could not change hex to vector");
    let key_vec = common::string_to_hex(key).expect("Could not change key to vector");

    let xor = two::xor_bytes(hex_vec.as_slice(), key_vec.as_slice()).expect("Could not Xor");
    debug!("XOR vector length {}", xor.len());
    let xor_string =
        common::hex_to_string(xor.as_slice()).expect("Could not convert xor vector to string");
    debug!("XORed string: {}", xor_string);
    if xor_string.as_str() != test_string {
        return false;
    }
    debug!("Succesfully XORed string!");

    true
}

fn challenge_three(input: &str, min_trigrams: u8) -> bool {
    let input_hex = common::string_to_hex(input).expect("Could not turn input into byte vec");
    let matches = three::bruteforce(input_hex.as_slice(), min_trigrams, false)
        .expect("Could not bruteforce string");
    debug!("Found {} potential matches", matches.len(),);

    for cur in &matches {
        debug!(
            "Matched message: \"{}\"\n\tMessage used key: {}\n\tMessage contained {} trigrams",
            cur.msg.blue(),
            cur.key,
            cur.trigrams
        );
    }

    if matches[0].key != 88 {
        return false;
    }
    debug!("Succesfully found XOR key!");

    true
}

fn challenge_four(path: &str, min_trigrams: u8) -> bool {
    debug!("Looking for encrypted strings in {}", path);
    let matches =
        four::find_encrypted_string(path, min_trigrams).expect("Could not find any matches");
    debug!("Found {} potential matches", matches.len(),);

    for cur in &matches {
        debug!(
            "Matched message: \"{}\"\n\tMessage used key: {}\n\tMessage contained {} trigrams",
            cur.msg.blue(),
            cur.key,
            cur.trigrams
        );
    }

    if matches[0].key != 53 {
        return false;
    }
    debug!("Succesfully found encrypted string key!");

    true
}

fn challenge_five(input: &str, key: &str, test_string: &str) -> bool {
    debug!("Encrypting string with repeating key XOR");
    let line_string = String::from(input);
    let input_bytes = line_string.as_bytes();
    debug!("Input bytes len: {}", input_bytes.len());
    let key_string = String::from(key);
    let key_bytes = key_string.as_bytes();
    debug!("Original key of length: {}", key_bytes.len());
    let extended_key = five::repeat_key(input_bytes.len(), key_bytes);
    debug!("Generated repeating key of length: {}", extended_key.len());
    let encrypted_bytes =
        two::xor_bytes(input_bytes, extended_key.as_slice()).expect("Could not encrypt input");

    let encrypted_hex = common::hex_to_string(encrypted_bytes.as_slice())
        .expect("Could not convert hex to string");

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

#[cfg(test)]
mod tests {

    #[test]
    fn challenge_one() {
        assert!(
            super::challenge_one(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            )
        );
    }

    #[test]
    fn challenge_two() {
        assert!(super::challenge_two(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
            "746865206b696420646f6e277420706c6179",
        ));
    }

    #[test]
    fn challenge_three() {
        assert!(super::challenge_three(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            1,
        ));
    }

    #[test]
    fn challenge_four() {
        assert!(super::challenge_four("./resources/four.txt", 3));
    }

    #[test]
    fn challenge_five() {
        assert!(super::challenge_five(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\na282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        ));
    }
}
