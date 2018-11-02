#[macro_use]
extern crate log;
extern crate colored;

pub mod one;

use colored::*;

fn main() {
    challenge_one("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
}

fn challenge_one(test_string: &str) {
    println!("{}", "Starting exercise one - base64 encoding".blue());
    println!(
        "{} {}",
        "Encoding hex String:".blue(),
        test_string.blue().bold()
    );
    let hex_string = one::string_to_hex(test_string).expect("Could not convert string");
    let hex_len = hex_string.len();
    let output = one::base64_encode(hex_string).expect("Could not base64 encode");
    println!(
        "{} {}",
        "Generaged encoded string: ".blue(),
        output.blue().bold()
    );
    assert_eq!(
        output.as_str(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        "{}",
        "Could not encode string".red().bold()
    );
    println!("{}", "Succesfully encoded string!".green().bold());

    println!("{}", "Attempting to decode string again".blue());
    let decoded_vec = one::base64_decode(&output).expect("Could not decode");
    println!(
        "Decoded len: {}. Original len: {}",
        decoded_vec.len(),
        hex_len
    );
    let decoded_string =
        one::hex_to_string(decoded_vec.as_slice()).expect("Could not turn vector to string");
    println!(
        "{} {}",
        "Decoded string:".blue(),
        decoded_string.blue().bold()
    );
    assert_eq!(
        test_string,
        decoded_string,
        "{}",
        "Could not decode string".red().bold()
    );
    println!("{}", "Succesfully decoded string!".green().bold());
}
