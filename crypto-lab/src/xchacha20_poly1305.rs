//! Educational XChaCha20-Poly1305 implementation.
//!
//! This module exists to study RFC 8439 and the XChaCha draft against
//! published test vectors. It is not constant-time reviewed, hardened, or
//! suitable for production use.

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const TAG_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidCiphertextLength,
    InvalidTag,
}

pub fn hchacha20(key: &[u8; KEY_BYTES], nonce: &[u8; 16]) -> [u8; KEY_BYTES] {
    let mut state = initial_hchacha20_state(key, nonce);
    chacha20_rounds(&mut state);

    let mut out = [0u8; KEY_BYTES];
    for (chunk, word) in out.chunks_exact_mut(4).zip([
        state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15],
    ]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }

    out
}

pub fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let key = fixed_array::<KEY_BYTES>(key).ok_or(Error::InvalidKeyLength)?;
    let nonce = fixed_array::<NONCE_BYTES>(nonce).ok_or(Error::InvalidNonceLength)?;
    let (subkey, chacha_nonce) = xchacha20_subkey_and_nonce(key, nonce);
    let poly1305_key = chacha20_block(&subkey, 0, &chacha_nonce);
    let ciphertext = chacha20_xor(&subkey, 1, &chacha_nonce, plaintext);
    let tag = poly1305_mac(&aead_mac_data(aad, &ciphertext), &poly1305_key[..32]);

    let mut out = Vec::with_capacity(ciphertext.len() + TAG_BYTES);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = fixed_array::<KEY_BYTES>(key).ok_or(Error::InvalidKeyLength)?;
    let nonce = fixed_array::<NONCE_BYTES>(nonce).ok_or(Error::InvalidNonceLength)?;
    if ciphertext_and_tag.len() < TAG_BYTES {
        return Err(Error::InvalidCiphertextLength);
    }

    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_BYTES);
    let (subkey, chacha_nonce) = xchacha20_subkey_and_nonce(key, nonce);
    let poly1305_key = chacha20_block(&subkey, 0, &chacha_nonce);
    let expected_tag = poly1305_mac(&aead_mac_data(aad, ciphertext), &poly1305_key[..32]);

    if !constant_time_eq(tag, &expected_tag) {
        return Err(Error::InvalidTag);
    }

    Ok(chacha20_xor(&subkey, 1, &chacha_nonce, ciphertext))
}

fn fixed_array<const N: usize>(bytes: &[u8]) -> Option<&[u8; N]> {
    bytes.try_into().ok()
}

fn xchacha20_subkey_and_nonce(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> ([u8; KEY_BYTES], [u8; 12]) {
    let hchacha_nonce = fixed_array::<16>(&nonce[..16]).expect("slice length is fixed");
    let subkey = hchacha20(key, hchacha_nonce);
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce[4..].copy_from_slice(&nonce[16..]);
    (subkey, chacha_nonce)
}

fn initial_chacha20_state(key: &[u8; KEY_BYTES], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;

    for (word, chunk) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4-byte key chunk"));
    }

    state[12] = counter;
    for (word, chunk) in state[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4-byte nonce chunk"));
    }

    state
}

fn initial_hchacha20_state(key: &[u8; KEY_BYTES], nonce: &[u8; 16]) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;

    for (word, chunk) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4-byte key chunk"));
    }
    for (word, chunk) in state[12..16].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4-byte nonce chunk"));
    }

    state
}

fn chacha20_block(key: &[u8; KEY_BYTES], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let initial = initial_chacha20_state(key, counter, nonce);
    let mut state = initial;
    chacha20_rounds(&mut state);

    for (word, initial_word) in state.iter_mut().zip(initial) {
        *word = word.wrapping_add(initial_word);
    }

    let mut out = [0u8; 64];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn chacha20_xor(
    key: &[u8; KEY_BYTES],
    initial_counter: u32,
    nonce: &[u8; 12],
    input: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (block_index, chunk) in input.chunks(64).enumerate() {
        let counter = initial_counter.wrapping_add(block_index as u32);
        let block = chacha20_block(key, counter, nonce);
        out.extend(
            chunk
                .iter()
                .zip(block)
                .map(|(byte, key_byte)| byte ^ key_byte),
        );
    }
    out
}

fn chacha20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn aead_mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(aad);
    pad16(&mut out);
    out.extend_from_slice(ciphertext);
    pad16(&mut out);
    out.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out
}

fn pad16(out: &mut Vec<u8>) {
    let padding = (16 - out.len() % 16) % 16;
    out.resize(out.len() + padding, 0);
}

fn poly1305_mac(message: &[u8], key: &[u8]) -> [u8; TAG_BYTES] {
    let r0 = u32::from_le_bytes(key[0..4].try_into().expect("r0")) as u64;
    let r1 = u32::from_le_bytes(key[4..8].try_into().expect("r1")) as u64;
    let r2 = u32::from_le_bytes(key[8..12].try_into().expect("r2")) as u64;
    let r3 = u32::from_le_bytes(key[12..16].try_into().expect("r3")) as u64;

    let r = [
        r0 & 0x03ff_ffff,
        ((r0 >> 26) | (r1 << 6)) & 0x03ff_ff03,
        ((r1 >> 20) | (r2 << 12)) & 0x03ff_c0ff,
        ((r2 >> 14) | (r3 << 18)) & 0x03f0_3fff,
        (r3 >> 8) & 0x000f_ffff,
    ];
    let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
    let mut h = [0u64; 5];

    for chunk in message.chunks(16) {
        add_poly1305_block(&mut h, chunk);
        multiply_poly1305(&mut h, &r, &s);
    }

    finalize_poly1305(h, &key[16..32])
}

fn add_poly1305_block(h: &mut [u64; 5], chunk: &[u8]) {
    let mut block = [0u8; 16];
    block[..chunk.len()].copy_from_slice(chunk);

    let full_block = chunk.len() == 16;
    if !full_block {
        block[chunk.len()] = 1;
    }

    let t0 = u32::from_le_bytes(block[0..4].try_into().expect("t0")) as u64;
    let t1 = u32::from_le_bytes(block[4..8].try_into().expect("t1")) as u64;
    let t2 = u32::from_le_bytes(block[8..12].try_into().expect("t2")) as u64;
    let t3 = u32::from_le_bytes(block[12..16].try_into().expect("t3")) as u64;

    h[0] += t0 & 0x03ff_ffff;
    h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
    h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
    h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
    h[4] += t3 >> 8;
    if full_block {
        h[4] += 1 << 24;
    }
}

fn multiply_poly1305(h: &mut [u64; 5], r: &[u64; 5], s: &[u64; 4]) {
    let d = [
        h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0],
        h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1],
        h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2],
        h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3],
        h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0],
    ];

    h[0] = d[0] & 0x03ff_ffff;
    let mut carry = d[0] >> 26;
    h[1] = (d[1] + carry) & 0x03ff_ffff;
    carry = (d[1] + carry) >> 26;
    h[2] = (d[2] + carry) & 0x03ff_ffff;
    carry = (d[2] + carry) >> 26;
    h[3] = (d[3] + carry) & 0x03ff_ffff;
    carry = (d[3] + carry) >> 26;
    h[4] = (d[4] + carry) & 0x03ff_ffff;
    carry = (d[4] + carry) >> 26;
    h[0] += carry * 5;
    carry = h[0] >> 26;
    h[0] &= 0x03ff_ffff;
    h[1] += carry;
}

fn finalize_poly1305(mut h: [u64; 5], s: &[u8]) -> [u8; TAG_BYTES] {
    propagate_carries(&mut h);

    let mut g = [0i64; 5];
    g[0] = h[0] as i64 + 5;
    let mut carry = g[0] >> 26;
    g[0] &= 0x03ff_ffff;
    for i in 1..4 {
        g[i] = h[i] as i64 + carry;
        carry = g[i] >> 26;
        g[i] &= 0x03ff_ffff;
    }
    g[4] = h[4] as i64 + carry - (1 << 26);

    if g[4] >= 0 {
        h = [
            g[0] as u64,
            g[1] as u64,
            g[2] as u64,
            g[3] as u64,
            g[4] as u64,
        ];
    }

    let mut f = [
        (h[0] | (h[1] << 26)) & 0xffff_ffff,
        ((h[1] >> 6) | (h[2] << 20)) & 0xffff_ffff,
        ((h[2] >> 12) | (h[3] << 14)) & 0xffff_ffff,
        ((h[3] >> 18) | (h[4] << 8)) & 0xffff_ffff,
    ];

    for (word, chunk) in f.iter_mut().zip(s.chunks_exact(4)) {
        *word += u32::from_le_bytes(chunk.try_into().expect("s word")) as u64;
    }

    let mut out = [0u8; TAG_BYTES];
    let mut carry = 0u64;
    for (word, chunk) in f.into_iter().zip(out.chunks_exact_mut(4)) {
        let value = word + carry;
        chunk.copy_from_slice(&(value as u32).to_le_bytes());
        carry = value >> 32;
    }

    out
}

fn propagate_carries(h: &mut [u64; 5]) {
    let mut carry = h[1] >> 26;
    h[1] &= 0x03ff_ffff;
    h[2] += carry;
    carry = h[2] >> 26;
    h[2] &= 0x03ff_ffff;
    h[3] += carry;
    carry = h[3] >> 26;
    h[3] &= 0x03ff_ffff;
    h[4] += carry;
    carry = h[4] >> 26;
    h[4] &= 0x03ff_ffff;
    h[0] += carry * 5;
    carry = h[0] >> 26;
    h[0] &= 0x03ff_ffff;
    h[1] += carry;
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right)
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, hchacha20, poly1305_mac};

    #[test]
    fn draft_hchacha20_test_vector() {
        let key: [u8; 32] =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid hex")
                .try_into()
                .expect("32-byte key");
        let nonce: [u8; 16] = hex::decode("000000090000004a0000000031415927")
            .expect("valid hex")
            .try_into()
            .expect("16-byte nonce");
        let expected = hex::decode(
            "82413b4227b27bfed30e42508a877d73\
             a0f9e4d58a74a853c12ec41326d3ecdc",
        )
        .expect("valid hex");

        assert_eq!(hchacha20(&key, &nonce), expected.as_slice());
    }

    #[test]
    fn rfc_8439_poly1305_test_vector() {
        let key = hex::decode(
            "85d6be7857556d337f4452fe42d506a8\
             0103808afb0db2fd4abff6af4149f51b",
        )
        .expect("valid hex");
        let message = b"Cryptographic Forum Research Group";
        let expected = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").expect("valid hex");

        assert_eq!(poly1305_mac(message, &key), expected.as_slice());
    }

    #[test]
    fn draft_aead_xchacha20_poly1305_test_vector_encrypts() {
        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .expect("valid hex");
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("valid hex");
        let key = hex::decode(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        )
        .expect("valid hex");
        let nonce = hex::decode(
            "404142434445464748494a4b4c4d4e4f\
             5051525354555657",
        )
        .expect("valid hex");
        let expected_ciphertext = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        )
        .expect("valid hex");
        let expected_tag = hex::decode("c0875924c1c7987947deafd8780acf49").expect("valid hex");

        let mut expected = expected_ciphertext;
        expected.extend_from_slice(&expected_tag);

        let actual = encrypt(&key, &nonce, &aad, &plaintext).expect("vector encrypts");

        assert_eq!(actual, expected);
    }

    #[test]
    fn draft_aead_xchacha20_poly1305_test_vector_decrypts() {
        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .expect("valid hex");
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").expect("valid hex");
        let key = hex::decode(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        )
        .expect("valid hex");
        let nonce = hex::decode(
            "404142434445464748494a4b4c4d4e4f\
             5051525354555657",
        )
        .expect("valid hex");
        let ciphertext_and_tag = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49",
        )
        .expect("valid hex");

        let actual = decrypt(&key, &nonce, &aad, &ciphertext_and_tag).expect("vector decrypts");

        assert_eq!(actual, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_aad_ciphertext_and_tag() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let aad = b"metadata";
        let plaintext = b"educational plaintext";
        let ciphertext_and_tag = encrypt(&key, &nonce, aad, plaintext).expect("encrypts");

        let mut tampered_aad = aad.to_vec();
        tampered_aad[0] ^= 1;
        assert!(decrypt(&key, &nonce, &tampered_aad, &ciphertext_and_tag).is_err());

        let mut tampered_ciphertext = ciphertext_and_tag.clone();
        tampered_ciphertext[0] ^= 1;
        assert!(decrypt(&key, &nonce, aad, &tampered_ciphertext).is_err());

        let mut tampered_tag = ciphertext_and_tag;
        let last = tampered_tag.len() - 1;
        tampered_tag[last] ^= 1;
        assert!(decrypt(&key, &nonce, aad, &tampered_tag).is_err());
    }
}
