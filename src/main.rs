#[macro_use]
extern crate log;
extern crate colored;
extern crate elapsed;
extern crate openssl;
extern crate simple_logger;

pub mod common;
pub mod eight;
pub mod five;
pub mod four;
pub mod one;
pub mod seven;
pub mod six;
pub mod three;
pub mod two;

use colored::*;
use elapsed::measure_time;

fn main() {
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    start_challenge("one", || {
        one::challenge_one(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        )
    });

    start_challenge("two", || {
        two::challenge_two(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
            "746865206b696420646f6e277420706c6179",
        )
    });

    start_challenge("three", || {
        three::challenge_three(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            88,
        )
    });

    start_challenge("four", || four::challenge_four("./resources/four.txt", 53));

    start_challenge("five", || {
        five::challenge_five(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\na282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
    });

    start_challenge("six", || {
        six::challenge_six(
            "./resources/six.txt",
            "Terminator X: Bring the noise",
            "I'm back and I'm",
        )
    });

    start_challenge("seven", || {
        seven::challenge_seven(
            "./resources/seven.txt",
            "YELLOW SUBMARINE",
            "I'm back and I'm ringin' the bell",
        )
    });

    start_challenge("eight", || {
        eight::challenge_eight("./resources/eight.txt", 132)
    });
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

#[cfg(test)]
mod tests {
    use eight;
    use five;
    use four;
    use one;
    use seven;
    use six;
    use three;
    use two;

    #[test]
    fn challenge_one() {
        assert!(
            one::challenge_one(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            )
        );
    }

    #[test]
    fn challenge_two() {
        assert!(two::challenge_two(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
            "746865206b696420646f6e277420706c6179",
        ));
    }

    #[test]
    fn challenge_three() {
        assert!(three::challenge_three(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            88,
        ));
    }

    #[test]
    fn challenge_four() {
        assert!(four::challenge_four("./resources/four.txt", 53));
    }

    #[test]
    fn challenge_five() {
        assert!(five::challenge_five(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\na282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        ));
    }

    #[test]
    fn challenge_six() {
        assert!(six::challenge_six(
            "./resources/six.txt",
            "Terminator X: Bring the noise",
            "I'm back and I'm"
        ));
    }

    #[test]
    fn challenge_seven() {
        assert!(seven::challenge_seven(
            "./resources/seven.txt",
            "YELLOW SUBMARINE",
            "I'm back and I'm ringin' the bell",
        ));
    }

    #[test]
    fn challenge_eight() {
        assert!(eight::challenge_eight("./resources/eight.txt", 132));
    }
}
