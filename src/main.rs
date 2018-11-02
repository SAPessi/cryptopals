#[macro_use]
extern crate log;
extern crate colored;

pub mod common;
pub mod one;
pub mod three;
pub mod two;

use colored::*;

fn main() {
    challenge_one(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    challenge_two(
        "1c0111001f010100061a024b53535009181c",
        "686974207468652062756c6c277320657965",
        "746865206b696420646f6e277420706c6179",
    );

    challenge_three(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        1,
    )
}

fn challenge_one(hex: &str, test_string: &str) {
    println!("{}", "Starting exercise one - base64 encoding".blue());
    println!("{} {}", "Encoding hex String:".blue(), hex.blue().bold());
    let hex_string = common::string_to_hex(hex).expect("Could not convert string");
    let hex_len = hex_string.len();
    let output = one::base64_encode(hex_string).expect("Could not base64 encode");
    println!(
        "{} {}",
        "Generaged encoded string: ".blue(),
        output.blue().bold()
    );
    assert_eq!(
        output.as_str(),
        test_string,
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
        common::hex_to_string(decoded_vec.as_slice()).expect("Could not turn vector to string");
    println!(
        "{} {}",
        "Decoded string:".blue(),
        decoded_string.blue().bold()
    );
    assert_eq!(
        hex,
        decoded_string,
        "{}",
        "Could not decode string".red().bold()
    );
    println!("{}", "Succesfully decoded string!".green().bold());
}

fn challenge_two(hex: &str, key: &str, test_string: &str) {
    println!(
        "{} {} {} {}",
        "XORing:".blue(),
        hex.blue().bold(),
        "with key: ".blue(),
        key.blue().bold()
    );
    let hex_vec = common::string_to_hex(hex).expect("Could not change hex to vector");
    let key_vec = common::string_to_hex(key).expect("Could not change key to vector");

    let xor = two::xor_bytes(hex_vec.as_slice(), key_vec.as_slice()).expect("Could not Xor");
    println!("{} {}", "XOR vector length".blue(), xor.len());
    let xor_string =
        common::hex_to_string(xor.as_slice()).expect("Could not convert xor vector to string");
    println!("{} {}", "XORed string:".blue(), xor_string.blue().bold());
    assert_eq!(
        xor_string.as_str(),
        test_string,
        "{}",
        "Xorred string is wrong".red().bold()
    );
    println!("{}", "Succesfully XORed string!".green().bold());
}

fn challenge_three(input: &str, min_trigrams: u8) {
    let input_hex = common::string_to_hex(input).expect("Could not turn input into byte vec");
    let matches = three::bruteforce(input_hex.as_slice(), min_trigrams, false)
        .expect("Could not bruteforce string");
    println!(
        "{} {} {}",
        "Found".blue(),
        matches.len(),
        "potential matches".blue()
    );

    for cur in &matches {
        println!(
            "{} {}: {} {}",
            "Match ".blue(),
            cur.msg.blue(),
            cur.key,
            cur.trigrams
        );
    }

    assert_eq!(
        matches[0].key,
        88,
        "{}",
        "Could not find string".red().bold()
    );
    println!("{}", "Succesfully found XOR key!".green().bold());
}
