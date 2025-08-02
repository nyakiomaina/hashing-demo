use std::io::{self, Write};
use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest as _};
use blake2::Blake2b512;
use md5::compute;
use tiny_keccak::{Hasher, Keccak};
use dialoguer::Select;
use hex::encode;

fn hash_text(input: &str, algorithm: &str) -> String {
    match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            encode(hasher.finalize())
        }
        "Keccak-256" => {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(input.as_bytes());
            keccak.finalize(&mut output);
            encode(output)
        }
        "Blake2b" => {
            let mut hasher = Blake2b512::new();
            hasher.update(input.as_bytes());
            encode(hasher.finalize())
        }
        "MD5" => {
            encode(compute(input.as_bytes()).0)
        }
        _ => unreachable!(),
    }
}

fn hash_file(file_path: &str, algorithm: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(file_path);

    if !path.exists() {
        return Err(format!("File '{}' does not exist", file_path).into());
    }

    if !path.is_file() {
        return Err(format!("'{}' is not a file", file_path).into());
    }

    let file_content = fs::read(file_path)?;

    Ok(match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(&file_content);
            encode(hasher.finalize())
        }
        "Keccak-256" => {
            let mut keccak = Keccak::v256();
            let mut output = [0u8; 32];
            keccak.update(&file_content);
            keccak.finalize(&mut output);
            encode(output)
        }
        "Blake2b" => {
            let mut hasher = Blake2b512::new();
            hasher.update(&file_content);
            encode(hasher.finalize())
        }
        "MD5" => {
            encode(compute(&file_content).0)
        }
        _ => unreachable!(),
    })
}

fn compare_hashes() {

    let compare_mode_choices = vec!["Compare Text", "Compare Files"];
    let compare_mode = Select::new()
        .with_prompt("Choose comparison mode")
        .items(&compare_mode_choices)
        .default(0)
        .interact()
        .unwrap();

    let (input1, input2, input_type) = match compare_mode {
        0 => {
            print!("Enter first text: ");
            io::stdout().flush().unwrap();
            let mut input1 = String::new();
            io::stdin().read_line(&mut input1).unwrap();
            let input1 = input1.trim();

            print!("Enter second text: ");
            io::stdout().flush().unwrap();
            let mut input2 = String::new();
            io::stdin().read_line(&mut input2).unwrap();
            let input2 = input2.trim();

            (input1.to_string(), input2.to_string(), "Text")
        }
        1 => {
            print!("Enter first file path: ");
            io::stdout().flush().unwrap();
            let mut input1 = String::new();
            io::stdin().read_line(&mut input1).unwrap();
            let input1 = input1.trim();

            print!("Enter second file path: ");
            io::stdout().flush().unwrap();
            let mut input2 = String::new();
            io::stdin().read_line(&mut input2).unwrap();
            let input2 = input2.trim();

            (input1.to_string(), input2.to_string(), "File")
        }
        _ => unreachable!(),
    };

    let choices = vec!["SHA-256", "Keccak-256", "Blake2b", "MD5"];
    let selection = Select::new()
        .with_prompt("Choose a hashing algorithm")
        .items(&choices)
        .default(0)
        .interact()
        .unwrap();

    let algorithm = choices[selection];

    let hash1_result = match compare_mode {
        0 => Ok(hash_text(&input1, algorithm)),
        1 => hash_file(&input1, algorithm),
        _ => unreachable!(),
    };

    let hash2_result = match compare_mode {
        0 => Ok(hash_text(&input2, algorithm)),
        1 => hash_file(&input2, algorithm),
        _ => unreachable!(),
    };

    match (hash1_result, hash2_result) {
        (Ok(hash1), Ok(hash2)) => {
            println!("\nComparison Results:");
            println!("Algorithm: {}", algorithm);
            println!("Type: {}", input_type);
            println!();
            println!("Input 1: '{}'", input1);
            println!("Hash 1:  {}", hash1);
            println!();
            println!("Input 2: '{}'", input2);
            println!("Hash 2:  {}", hash2);
            println!();

            if hash1 == hash2 {
            } else {
                let differences = hash1.chars().zip(hash2.chars())
                    .filter(|(a, b)| a != b)
                    .count();
                let total_chars = hash1.len();
                let difference_percentage = (differences as f64 / total_chars as f64) * 100.0;

                println!("Character differences: {}/{} ({:.1}%)", differences, total_chars, difference_percentage);
            }
        }
        (Err(e), _) => {
            eprintln!("Error with first input: {}", e);
        }
        (_, Err(e)) => {
            eprintln!("Error with second input: {}", e);
        }
    }
}

fn main() {
    println!("Hashing Function Demo");

    loop {
        let mode_choices = vec!["Text Hashing", "File Hashing", "Compare Hashes"];
        let mode_selection = Select::new()
            .with_prompt("Choose hashing mode")
            .items(&mode_choices)
            .default(0)
            .interact()
            .unwrap();

        match mode_selection {
            0 | 1 => {
                let (input, input_type) = match mode_selection {
                    0 => {
                        print!("Enter text to hash: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        let input = input.trim();
                        (input.to_string(), "Text")
                    }
                    1 => {
                        print!("Enter file path to hash: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        let input = input.trim();
                        (input.to_string(), "File")
                    }
                    _ => unreachable!(),
                };

                let choices = vec!["SHA-256", "Keccak-256", "Blake2b", "MD5"];
                let selection = Select::new()
                    .with_prompt("Choose a hashing algorithm")
                    .items(&choices)
                    .default(0)
                    .interact()
                    .unwrap();

                let algorithm = choices[selection];
                let hash_result = match mode_selection {
                    0 => {
                        Ok(hash_text(&input, algorithm))
                    }
                    1 => {
                        hash_file(&input, algorithm)
                    }
                    _ => unreachable!(),
                };

                match hash_result {
                    Ok(hash) => {
                        println!("\nInput: '{}'", input);
                        println!("Type: {}", input_type);
                        println!("Algorithm: {}", algorithm);
                        println!("Output Hash: {}\n", hash);

                        match selection {
                            0 => println!("SHA-256 is widely used in Bitcoin & general cryptography."),
                            1 => println!("Keccak-256 is used in Ethereum smart contracts."),
                            2 => println!("Blake2b is fast and secure. Used in modern protocols like Zcash."),
                            3 => println!("MD5 is broken. Do NOT use it for security-critical tasks."),
                            _ => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            2 => {
                compare_hashes();
            }
            _ => unreachable!(),
        }

        let continue_choices = vec!["Continue Hashing", "Exit"];
        let continue_selection = Select::new()
            .items(&continue_choices)
            .default(0)
            .interact()
            .unwrap();

        if continue_selection == 1 {
            println!("hope you learned something!");
            break;
        }

        println!();
    }
}
