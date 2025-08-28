use std::fmt::Display;

use aes_siv::{Key, KeyInit, siv::Aes128Siv, siv::Aes256Siv};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::extension_fields::ExtensionField;

#[derive(Debug)]
pub struct DecryptError;

impl Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not decrypt ciphertext")
    }
}

impl std::error::Error for DecryptError {}

struct Buffer<'a> {
    buffer: &'a mut [u8],
    valid: usize,
}

impl<'a> Buffer<'a> {
    fn new(buffer: &'a mut [u8], valid: usize) -> Self {
        Self { buffer, valid }
    }

    fn valid(&self) -> usize {
        self.valid
    }
}

impl AsMut<[u8]> for Buffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.valid]
    }
}

impl AsRef<[u8]> for Buffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.valid]
    }
}

impl aead::Buffer for Buffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buffer
            .get_mut(self.valid..(self.valid + other.len()))
            .ok_or(aead::Error)?
            .copy_from_slice(other);
        self.valid += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.valid = std::cmp::min(self.valid, len);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptResult {
    pub nonce_length: usize,
    pub ciphertext_length: usize,
}

pub trait Cipher: Sync + Send + ZeroizeOnDrop + 'static {
    /// encrypts the plaintext present in the buffer
    ///
    /// - encrypts `plaintext_length` bytes from the buffer
    /// - puts the nonce followed by the ciphertext into the buffer
    /// - returns the size of the nonce and ciphertext
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult>;

    // MUST support arbitrary length nonces
    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError>;
}

pub enum CipherHolder<'a> {
    Other(&'a dyn Cipher),
}

impl AsRef<dyn Cipher> for CipherHolder<'_> {
    fn as_ref(&self) -> &dyn Cipher {
        match self {
            CipherHolder::Other(cipher) => *cipher,
        }
    }
}

pub trait CipherProvider {
    fn get(&self, context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>>;
}

#[cfg(test)]
pub struct NoCipher;

#[cfg(test)]
impl CipherProvider for NoCipher {
    fn get<'a>(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        None
    }
}

impl CipherProvider for dyn Cipher {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        Some(CipherHolder::Other(self))
    }
}

impl CipherProvider for Option<&dyn Cipher> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.map(CipherHolder::Other)
    }
}

impl<C: Cipher> CipherProvider for C {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        Some(CipherHolder::Other(self))
    }
}

impl<C: Cipher> CipherProvider for Option<C> {
    fn get(&self, _context: &[ExtensionField<'_>]) -> Option<CipherHolder<'_>> {
        self.as_ref().map(|v| CipherHolder::Other(v))
    }
}

pub struct AesSivCmac256 {
    // 128 vs 256 difference is due to using the official name (us) vs
    // the number of bits of security (aes_siv crate)
    key: Key<Aes128Siv>,
}

impl ZeroizeOnDrop for AesSivCmac256 {}

impl AesSivCmac256 {
    pub fn new(key: Key<Aes128Siv>) -> Self {
        AesSivCmac256 { key }
    }
}

impl Drop for AesSivCmac256 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Cipher for AesSivCmac256 {
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes128Siv::new(&self.key);
        let nonce: [u8; 16] = rand::rng().random();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(&mut buffer[nonce.len()..], plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut siv = Aes128Siv::new(&self.key);
        siv.decrypt([associated_data, nonce], ciphertext)
            .map_err(|_| DecryptError)
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac256").finish()
    }
}

pub struct AesSivCmac512 {
    // 256 vs 512 difference is due to using the official name (us) vs
    // the number of bits of security (aes_siv crate)
    key: Key<Aes256Siv>,
}

impl AesSivCmac512 {
    pub fn new(key: Key<Aes256Siv>) -> Self {
        AesSivCmac512 { key }
    }
}

impl ZeroizeOnDrop for AesSivCmac512 {}

impl Drop for AesSivCmac512 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Cipher for AesSivCmac512 {
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        let mut siv = Aes256Siv::new(&self.key);
        let nonce: [u8; 16] = rand::rng().random();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        // Create a wrapper around the plaintext portion of the buffer that has
        // the methods aes_siv needs to do encryption in-place.
        let mut buffer_wrap = Buffer::new(&mut buffer[nonce.len()..], plaintext_length);
        siv.encrypt_in_place([associated_data, &nonce], &mut buffer_wrap)
            .map_err(|_| std::io::ErrorKind::Other)?;

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: buffer_wrap.valid(),
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut siv = Aes256Siv::new(&self.key);
        siv.decrypt([associated_data, nonce], ciphertext)
            .map_err(|_| DecryptError)
    }
}

// Ensure siv is not shown in debug output
impl std::fmt::Debug for AesSivCmac512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesSivCmac512").finish()
    }
}

#[cfg(test)]
pub struct IdentityCipher {
    nonce_length: usize,
}

#[cfg(test)]
impl IdentityCipher {
    pub fn new(nonce_length: usize) -> Self {
        Self { nonce_length }
    }
}

#[cfg(test)]
impl ZeroizeOnDrop for IdentityCipher {}

#[cfg(test)]
impl Cipher for IdentityCipher {
    fn encrypt(
        &self,
        buffer: &mut [u8],
        plaintext_length: usize,
        associated_data: &[u8],
    ) -> std::io::Result<EncryptResult> {
        debug_assert!(associated_data.is_empty());

        let nonce: Vec<u8> = (0..self.nonce_length as u8).collect();

        // Prepare the buffer for in place encryption by moving the plaintext
        // back, creating space for the nonce.
        if buffer.len() < nonce.len() + plaintext_length {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buffer.copy_within(..plaintext_length, nonce.len());
        // And place the nonce where the caller expects it
        buffer[..nonce.len()].copy_from_slice(&nonce);

        Ok(EncryptResult {
            nonce_length: nonce.len(),
            ciphertext_length: plaintext_length,
        })
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        debug_assert!(associated_data.is_empty());

        debug_assert_eq!(nonce.len(), self.nonce_length);

        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_siv_cmac_256() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac256::new([0u8; 32].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[]).unwrap();
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_256_with_assoc_data() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac256::new([0u8; 32].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[1]).unwrap();
        assert!(
            key.decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2]
            )
            .is_err()
        );
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_512() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac512::new([0u8; 64].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[]).unwrap();
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }

    #[test]
    fn test_aes_siv_cmac_512_with_assoc_data() {
        let mut testvec: Vec<u8> = (0..16).collect();
        testvec.resize(testvec.len() + 32, 0);
        let key = AesSivCmac512::new([0u8; 64].into());
        let EncryptResult {
            nonce_length,
            ciphertext_length,
        } = key.encrypt(&mut testvec, 16, &[1]).unwrap();
        assert!(
            key.decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[2]
            )
            .is_err()
        );
        let result = key
            .decrypt(
                &testvec[..nonce_length],
                &testvec[nonce_length..(nonce_length + ciphertext_length)],
                &[1],
            )
            .unwrap();
        assert_eq!(result, (0..16).collect::<Vec<u8>>());
    }
}
