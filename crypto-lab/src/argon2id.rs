//! Educational Argon2id implementation based on RFC 9106.
//!
//! This module exists so we can study the construction against test vectors.
//! It is not constant-time reviewed, hardened, or suitable for production use.

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};

pub const ARGON2_VERSION_13: u32 = 0x13;
const ARGON2ID_TYPE: u32 = 2;
const SYNC_POINTS: u32 = 4;
const BLOCK_WORDS: usize = 128;
const BLOCK_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Params {
    pub lanes: u32,
    pub tag_len: u32,
    pub memory_kib: u32,
    pub passes: u32,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidParams,
}

pub fn hash(
    params: Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    validate_params(params)?;

    let lanes = params.lanes as usize;
    let memory_blocks = normalize_memory(params.memory_kib, params.lanes) as usize;
    let lane_length = memory_blocks / lanes;
    let segment_length = lane_length / SYNC_POINTS as usize;
    let h0 = initial_hash(params, password, salt, secret, associated_data);
    let mut memory = vec![Block::default(); memory_blocks];

    for lane in 0..lanes {
        memory[lane * lane_length] = initial_block(&h0, 0, lane as u32);
        memory[lane * lane_length + 1] = initial_block(&h0, 1, lane as u32);
    }

    for pass in 0..params.passes {
        for slice in 0..SYNC_POINTS {
            for lane in 0..params.lanes {
                fill_segment(
                    &mut memory,
                    pass,
                    slice,
                    lane,
                    params,
                    lane_length,
                    segment_length,
                );
            }
        }
    }

    let mut final_block = memory[lane_length - 1];
    for lane in 1..lanes {
        final_block.xor_in_place(&memory[lane * lane_length + lane_length - 1]);
    }

    Ok(variable_hash(
        &final_block.to_le_bytes(),
        params.tag_len as usize,
    ))
}

fn validate_params(params: Params) -> Result<(), Error> {
    if params.lanes == 0
        || params.tag_len == 0
        || params.memory_kib < 8 * params.lanes
        || params.passes == 0
        || params.version != ARGON2_VERSION_13
    {
        return Err(Error::InvalidParams);
    }

    Ok(())
}

fn normalize_memory(memory_kib: u32, lanes: u32) -> u32 {
    let minimum = 8 * lanes;
    let memory = memory_kib.max(minimum);
    memory - (memory % (lanes * SYNC_POINTS))
}

fn initial_hash(
    params: Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
) -> [u8; 64] {
    let mut input = Vec::new();
    push_u32(&mut input, params.lanes);
    push_u32(&mut input, params.tag_len);
    push_u32(&mut input, params.memory_kib);
    push_u32(&mut input, params.passes);
    push_u32(&mut input, params.version);
    push_u32(&mut input, ARGON2ID_TYPE);
    push_len_prefixed(&mut input, password);
    push_len_prefixed(&mut input, salt);
    push_len_prefixed(&mut input, secret);
    push_len_prefixed(&mut input, associated_data);

    let digest = Blake2b512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

fn initial_block(h0: &[u8; 64], block_index: u32, lane: u32) -> Block {
    let mut input = Vec::with_capacity(72);
    input.extend_from_slice(h0);
    push_u32(&mut input, block_index);
    push_u32(&mut input, lane);
    Block::from_le_bytes(&variable_hash(&input, BLOCK_BYTES))
}

fn variable_hash(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut initial = Vec::with_capacity(4 + input.len());
    push_u32(&mut initial, output_len as u32);
    initial.extend_from_slice(input);

    if output_len <= 64 {
        return blake2b_var(output_len, &initial);
    }

    let mut out = Vec::with_capacity(output_len);
    let mut digest = blake2b_512(&initial);
    out.extend_from_slice(&digest[..32]);

    while out.len() + 64 < output_len {
        digest = blake2b_512(&digest);
        out.extend_from_slice(&digest[..32]);
    }

    digest = blake2b_512(&digest);
    out.extend_from_slice(&digest[..output_len - out.len()]);
    out
}

fn blake2b_var(output_len: usize, input: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(output_len).expect("validated BLAKE2b output length");
    Update::update(&mut hasher, input);
    let mut out = vec![0u8; output_len];
    hasher
        .finalize_variable(&mut out)
        .expect("fixed-size output buffer");
    out
}

fn blake2b_512(input: &[u8]) -> [u8; 64] {
    let digest = Blake2b512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn fill_segment(
    memory: &mut [Block],
    pass: u32,
    slice: u32,
    lane: u32,
    params: Params,
    lane_length: usize,
    segment_length: usize,
) {
    let data_independent_addressing = pass == 0 && slice < SYNC_POINTS / 2;
    let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };
    let mut address_generator = data_independent_addressing.then(|| {
        AddressGenerator::new(
            pass,
            lane,
            slice,
            params,
            memory.len() as u32,
            starting_index,
        )
    });

    for index in starting_index..segment_length {
        let current_offset = lane as usize * lane_length + slice as usize * segment_length + index;
        let previous_offset = previous_offset(current_offset, lane_length);
        let pseudo_random = match address_generator.as_mut() {
            Some(generator) => generator.next(index),
            None => memory[previous_offset].words[0],
        };
        let reference_offset = reference_offset(
            pseudo_random,
            pass,
            slice,
            lane,
            index,
            params.lanes,
            lane_length,
            segment_length,
        );
        let with_xor = pass != 0;
        let next_block = compress(
            &memory[previous_offset],
            &memory[reference_offset],
            if with_xor {
                Some(&memory[current_offset])
            } else {
                None
            },
        );

        memory[current_offset] = next_block;
    }
}

fn previous_offset(current_offset: usize, lane_length: usize) -> usize {
    if current_offset.is_multiple_of(lane_length) {
        current_offset + lane_length - 1
    } else {
        current_offset - 1
    }
}

#[allow(clippy::too_many_arguments)]
fn reference_offset(
    pseudo_random: u64,
    pass: u32,
    slice: u32,
    lane: u32,
    index: usize,
    lanes: u32,
    lane_length: usize,
    segment_length: usize,
) -> usize {
    let mut reference_lane = ((pseudo_random >> 32) as u32 % lanes) as usize;
    if pass == 0 && slice == 0 {
        reference_lane = lane as usize;
    }

    let same_lane = reference_lane == lane as usize;
    let reference_area_size = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice as usize * segment_length + index - 1
        } else {
            slice as usize * segment_length + usize::from(index != 0) - 1
        }
    } else if same_lane {
        lane_length - segment_length + index - 1
    } else {
        lane_length - segment_length + usize::from(index != 0) - 1
    };

    let relative_position = map_to_reference_position(pseudo_random, reference_area_size as u64);
    let start_position = if pass == 0 || slice == SYNC_POINTS - 1 {
        0
    } else {
        (slice as usize + 1) * segment_length
    };
    let absolute_position = (start_position + relative_position) % lane_length;

    reference_lane * lane_length + absolute_position
}

fn map_to_reference_position(pseudo_random: u64, reference_area_size: u64) -> usize {
    let relative = pseudo_random & 0xffff_ffff;
    let relative = (relative * relative) >> 32;
    (reference_area_size - 1 - ((reference_area_size * relative) >> 32)) as usize
}

struct AddressGenerator {
    input_block: Block,
    address_block: Block,
}

impl AddressGenerator {
    fn new(
        pass: u32,
        lane: u32,
        slice: u32,
        params: Params,
        memory_blocks: u32,
        starting_index: usize,
    ) -> Self {
        let mut input_block = Block::default();
        input_block.words[0] = pass as u64;
        input_block.words[1] = lane as u64;
        input_block.words[2] = slice as u64;
        input_block.words[3] = memory_blocks as u64;
        input_block.words[4] = params.passes as u64;
        input_block.words[5] = ARGON2ID_TYPE as u64;

        let mut generator = Self {
            input_block,
            address_block: Block::default(),
        };

        if starting_index != 0 {
            generator.next_addresses();
        }

        generator
    }

    fn next(&mut self, index: usize) -> u64 {
        if index.is_multiple_of(BLOCK_WORDS) {
            self.next_addresses();
        }

        self.address_block.words[index % BLOCK_WORDS]
    }

    fn next_addresses(&mut self) {
        self.input_block.words[6] += 1;
        let zero = Block::default();
        let first = compress(&zero, &self.input_block, None);
        self.address_block = compress(&zero, &first, None);
    }
}

#[derive(Clone, Copy)]
struct Block {
    words: [u64; BLOCK_WORDS],
}

impl Default for Block {
    fn default() -> Self {
        Self {
            words: [0; BLOCK_WORDS],
        }
    }
}

impl Block {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), BLOCK_BYTES);
        let mut words = [0u64; BLOCK_WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        Self { words }
    }

    fn to_le_bytes(self) -> [u8; BLOCK_BYTES] {
        let mut bytes = [0u8; BLOCK_BYTES];
        for (word, chunk) in self.words.iter().zip(bytes.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn xor_in_place(&mut self, other: &Self) {
        for (left, right) in self.words.iter_mut().zip(other.words) {
            *left ^= right;
        }
    }
}

fn compress(previous: &Block, reference: &Block, current: Option<&Block>) -> Block {
    let mut r = Block::default();
    for i in 0..BLOCK_WORDS {
        r.words[i] = previous.words[i] ^ reference.words[i];
    }

    let mut z = r;
    for row in 0..8 {
        apply_permutation(&mut z.words, row_indices(row));
    }
    for column in 0..8 {
        apply_permutation(&mut z.words, column_indices(column));
    }

    for i in 0..BLOCK_WORDS {
        z.words[i] ^= r.words[i];
        if let Some(current) = current {
            z.words[i] ^= current.words[i];
        }
    }

    z
}

fn row_indices(row: usize) -> [usize; 16] {
    let start = row * 16;
    [
        start,
        start + 1,
        start + 2,
        start + 3,
        start + 4,
        start + 5,
        start + 6,
        start + 7,
        start + 8,
        start + 9,
        start + 10,
        start + 11,
        start + 12,
        start + 13,
        start + 14,
        start + 15,
    ]
}

fn column_indices(column: usize) -> [usize; 16] {
    let start = column * 2;
    [
        start,
        start + 1,
        start + 16,
        start + 17,
        start + 32,
        start + 33,
        start + 48,
        start + 49,
        start + 64,
        start + 65,
        start + 80,
        start + 81,
        start + 96,
        start + 97,
        start + 112,
        start + 113,
    ]
}

fn apply_permutation(words: &mut [u64; BLOCK_WORDS], indices: [usize; 16]) {
    let mut v = [0u64; 16];
    for (out, index) in v.iter_mut().zip(indices) {
        *out = words[index];
    }

    blake2b_round(&mut v, 0, 4, 8, 12);
    blake2b_round(&mut v, 1, 5, 9, 13);
    blake2b_round(&mut v, 2, 6, 10, 14);
    blake2b_round(&mut v, 3, 7, 11, 15);
    blake2b_round(&mut v, 0, 5, 10, 15);
    blake2b_round(&mut v, 1, 6, 11, 12);
    blake2b_round(&mut v, 2, 7, 8, 13);
    blake2b_round(&mut v, 3, 4, 9, 14);

    for (value, index) in v.into_iter().zip(indices) {
        words[index] = value;
    }
}

fn blake2b_round(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = gb_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = gb_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = gb_add(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = gb_add(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn gb_add(x: u64, y: u64) -> u64 {
    let low_product = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
    x.wrapping_add(y)
        .wrapping_add(2u64.wrapping_mul(low_product))
}

#[cfg(test)]
mod tests {
    use super::{hash, Params, ARGON2_VERSION_13};

    #[test]
    fn rfc_9106_argon2id_test_vector() {
        let params = Params {
            lanes: 4,
            tag_len: 32,
            memory_kib: 32,
            passes: 3,
            version: ARGON2_VERSION_13,
        };

        let password = [0x01; 32];
        let salt = [0x02; 16];
        let secret = [0x03; 8];
        let associated_data = [0x04; 12];
        let expected = hex::decode(
            "0d640df58d78766c08c037a34a8b53c9\
             d01ef0452d75b65eb52520e96b01e659",
        )
        .expect("valid hex test vector");

        let actual = hash(params, &password, &salt, &secret, &associated_data)
            .expect("Argon2id should hash RFC vector input");

        assert_eq!(actual, expected);
    }
}
