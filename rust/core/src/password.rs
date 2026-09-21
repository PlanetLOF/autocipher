//! Cryptographically secure random password generation.
//!
//! Passwords are drawn from a cryptographically secure RNG and grouped by
//! character class so that every generated password provably contains at least
//! one uppercase letter, one lowercase letter, one digit, and one symbol.

use rand::RngExt;

/// Default length of a generated password.
pub const DEFAULT_PASSWORD_LEN: usize = 20;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT: &[u8] = b"0123456789";
const SYMBOL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

/// Generate a random password of `length` bytes using a crypto-secure RNG.
///
/// When `length >= 4` the password always includes at least one character from
/// each class — uppercase, lowercase, digit, and symbol — with the remaining
/// characters drawn uniformly from the full union of all classes. For shorter
/// lengths (minimum 1, or empty when `length == 0`) every character is drawn
/// from the full union. The default 20-character length satisfies the
/// class guarantee.
pub fn generate_password(length: usize) -> String {
    if length == 0 {
        return String::new();
    }

    let classes: [&[u8]; 4] = [UPPER, LOWER, DIGIT, SYMBOL];
    let all: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut rng = rand::rng();
    let mut chosen = Vec::with_capacity(length);

    // Guarantee at least one character from every class when the requested
    // length allows it (four classes); shorter passwords are drawn uniformly
    // from the full set.
    if length >= classes.len() {
        for class in classes {
            chosen.push(class[rng.random_range(0..class.len())]);
        }
    }
    // Fill the remainder from the full set.
    while chosen.len() < length {
        chosen.push(all[rng.random_range(0..all.len())]);
    }

    // Shuffle so the guaranteed characters are not clustered at the front.
    let mut shuffled = Vec::with_capacity(length);
    while !chosen.is_empty() {
        let idx = rng.random_range(0..chosen.len());
        shuffled.push(chosen.swap_remove(idx));
    }

    String::from_utf8(shuffled).expect("all characters are valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn char_classes(s: &str) -> [bool; 4] {
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_symbol = false;
        for b in s.bytes() {
            if UPPER.contains(&b) {
                has_upper = true;
            } else if LOWER.contains(&b) {
                has_lower = true;
            } else if DIGIT.contains(&b) {
                has_digit = true;
            } else if SYMBOL.contains(&b) {
                has_symbol = true;
            }
        }
        [has_upper, has_lower, has_digit, has_symbol]
    }

    #[test]
    fn generates_requested_length() {
        for len in [1usize, 8, 20, 64] {
            assert_eq!(generate_password(len).len(), len);
        }
    }

    #[test]
    fn includes_every_character_class() {
        for _ in 0..128 {
            let pwd = generate_password(DEFAULT_PASSWORD_LEN);
            let [upper, lower, digit, symbol] = char_classes(&pwd);
            assert!(upper, "missing uppercase in {pwd}");
            assert!(lower, "missing lowercase in {pwd}");
            assert!(digit, "missing digit in {pwd}");
            assert!(symbol, "missing symbol in {pwd}");
        }
    }

    #[test]
    fn calls_produce_distinct_outputs() {
        let a = generate_password(DEFAULT_PASSWORD_LEN);
        let b = generate_password(DEFAULT_PASSWORD_LEN);
        assert_ne!(a, b);
    }

    #[test]
    fn zero_length_is_empty() {
        assert_eq!(generate_password(0), "");
    }

    #[test]
    fn all_characters_are_from_the_union() {
        let all: Vec<u8> = [UPPER, LOWER, DIGIT, SYMBOL]
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect();
        for _ in 0..64 {
            for b in generate_password(DEFAULT_PASSWORD_LEN).bytes() {
                assert!(all.contains(&b));
            }
        }
    }
}
