//! Constant-time byte comparison for passphrases and other secrets.

use subtle::{Choice, ConstantTimeEq};

/// Compare `a` and `b` for equality in constant time.
///
/// Both the length comparison and the byte comparison run in constant time
/// with respect to the contents (and length) of the inputs, so an attacker
/// observing timing cannot learn how many leading bytes match or how the
/// lengths differ.
pub fn compare_passphrase(a: &[u8], b: &[u8]) -> bool {
    let len_eq = a.len().ct_eq(&b.len());
    let max_len = a.len().max(b.len());
    let mut acc = Choice::from(1u8);
    for i in 0..max_len {
        let ab = a.get(i).copied().unwrap_or(0);
        let bb = b.get(i).copied().unwrap_or(0);
        acc &= ab.ct_eq(&bb);
    }
    // Equal only if lengths match and every byte matched (acc stays 1 only when
    // all bytes are equal).
    (len_eq & acc).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_inputs() {
        assert!(compare_passphrase(
            b"correct horse battery staple",
            b"correct horse battery staple"
        ));
    }

    #[test]
    fn equal_empty_inputs() {
        assert!(compare_passphrase(b"", b""));
    }

    #[test]
    fn unequal_same_length() {
        assert!(!compare_passphrase(
            b"correct horse battery staple",
            b"correct horse batterx staple"
        ));
    }

    #[test]
    fn unequal_single_byte() {
        assert!(!compare_passphrase(b"password", b"pas sword"));
    }

    #[test]
    fn unequal_length_shorter_first() {
        assert!(!compare_passphrase(b"short", b"much longer input"));
    }

    #[test]
    fn unequal_length_longer_first() {
        assert!(!compare_passphrase(b"much longer input", b"short"));
    }

    #[test]
    fn unequal_length_shared_prefix() {
        // Same prefix but different lengths must still be unequal.
        assert!(!compare_passphrase(b"secret", b"secretlong"));
        assert!(!compare_passphrase(b"secretlong", b"secret"));
    }
}
