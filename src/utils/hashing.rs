//! Fingerprints: Git object ID (SHA-1 blob) and SHA-256.

use sha1::{Digest, Sha1};
use sha2::Sha256;

/// Computes the Git object ID of a blob (SHA-1 format), identical to
/// `git hash-object`. Allows comparing a file on disk with a Git tree
/// without reading the blob content on the Git side.
pub fn git_blob_oid(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("blob {}\0", data.len()).as_bytes());
    h.update(data);
    hex::encode(h.finalize())
}

/// Hexadecimal SHA-256 hash.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_git_hash_object() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(git_blob_oid(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a");
        // empty blob
        assert_eq!(git_blob_oid(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }
}
