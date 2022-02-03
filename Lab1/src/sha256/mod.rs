use std::ops::Not;

const BLOCK_LENGTH_BYTES: usize = 64;       // 512 bits

const HASH_INIT_VECTOR: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub struct Sha256Gen {
    // intermediary hash
    int_hash: [u32; 8],
    last_block: [u8; 64],
    last_block_length: usize,
    total_length: usize,
}

impl Sha256Gen {
    pub fn new() -> Sha256Gen {
        Sha256Gen {
            int_hash: HASH_INIT_VECTOR,
            last_block: [0; 64],
            last_block_length: 0,
            total_length: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let input_length = bytes.len();

        if input_length + self.last_block_length < BLOCK_LENGTH_BYTES {
            let new_last_block_length = self.last_block_length + input_length;

            self.last_block[self.last_block_length..new_last_block_length].copy_from_slice(bytes);
            self.last_block_length = new_last_block_length;
            self.total_length += input_length;

            return;
        }

        let new_last_block_length = (self.last_block_length + input_length) % BLOCK_LENGTH_BYTES;
        let bytes_to_process = self.last_block_length + input_length - new_last_block_length;
        let chunks = bytes_to_process / BLOCK_LENGTH_BYTES;

        let b = |i: usize| if i < self.last_block_length { self.last_block[i] } else { bytes[i - self.last_block_length] } as u32;
        for chunk in 0..chunks {
            let mut w: [u32; 64] = [0; 64];
            for i in 0..BLOCK_LENGTH_BYTES {
                let j = i / 4;      // word index

                w[j] = w[j] << 8;
                w[j] = w[j] | b(chunk * BLOCK_LENGTH_BYTES + i);
            }

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^
                    w[i - 15] >> 3;
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^
                    w[i - 2] >> 10;

                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }

            let mut a = self.int_hash[0];
            let mut b = self.int_hash[1];
            let mut c = self.int_hash[2];
            let mut d = self.int_hash[3];
            let mut e = self.int_hash[4];
            let mut f = self.int_hash[5];
            let mut g = self.int_hash[6];
            let mut h = self.int_hash[7];

            for i in 0..64 {
                let s1 = (e.rotate_right(6)) ^ (e.rotate_right(11)) ^ (e.rotate_right(25));
                let ch = (e & f) ^ (e.not() & g);
                let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = (a.rotate_right(2)) ^ (a.rotate_right(13)) ^ (a.rotate_right(22));
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }

            self.int_hash[0] = self.int_hash[0].wrapping_add(a);
            self.int_hash[1] = self.int_hash[1].wrapping_add(b);
            self.int_hash[2] = self.int_hash[2].wrapping_add(c);
            self.int_hash[3] = self.int_hash[3].wrapping_add(d);
            self.int_hash[4] = self.int_hash[4].wrapping_add(e);
            self.int_hash[5] = self.int_hash[5].wrapping_add(f);
            self.int_hash[6] = self.int_hash[6].wrapping_add(g);
            self.int_hash[7] = self.int_hash[7].wrapping_add(h);
        }

        let last_block_begin = input_length - new_last_block_length;

        self.last_block[..new_last_block_length].copy_from_slice(&bytes[last_block_begin..]);
        self.last_block_length = new_last_block_length;
        self.total_length += input_length;
    }

    pub fn digest(&mut self) -> [u8; 32] {
        let padding = self.create_padding();

        self.update(&padding);

        assert_eq!(self.last_block_length, 0);

        let mut hash: [u8; 32] = [0; 32];

        for i in 0..32 {
            let j = i / 4;
            let offset = 3 - i % 4;

            hash[i] = ((self.int_hash[j] >> (8 * offset)) & 0xff) as u8;
        }

        hash
    }

    fn create_padding(&self) -> Vec<u8> {
        let total_size_bits = self.total_length * 8;

        let mut padding_length = 512 - total_size_bits % 512;

        if padding_length < 65 {
            padding_length += 512;
        }

        let padding_byte_count = padding_length / 8;

        let mut padding_bytes = vec![0; padding_byte_count];

        // pad first byte
        padding_bytes[0] = 1 << 7;

        let size_bytes = (total_size_bits as u64).to_be_bytes();
        padding_bytes[padding_byte_count - 8..].copy_from_slice(&size_bytes);

        padding_bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256::Sha256Gen;

    #[test]
    fn test_pad_empty() {
        let gen = Sha256Gen::new();

        let padding = gen.create_padding();
        assert_eq!(padding.len(), 64);
    }

    #[test]
    fn test_pad_single_zero() {
        let mut gen = Sha256Gen::new();

        gen.update(&[0]);

        let padding = gen.create_padding();
        assert_eq!(padding.len(), 63);

        let first_byte = padding[0];     // test whether 1 is set properly
        assert_eq!(first_byte, 0x80);

        let last_dword = padding[62];    // test whether length is set properly
        assert_eq!(last_dword, 8);
    }

    #[test]
    fn test_pad_four_zeros() {
        let mut gen = Sha256Gen::new();

        gen.update(&[0; 4]);

        let padding = gen.create_padding();

        assert_eq!(padding.len(), 60);

        let padding_begin_byte = padding[0];    // test whether 1 is set properly
        assert_eq!(padding_begin_byte, 0x80);

        let last_byte = padding[59];            // test whether length is set properly
        assert_eq!(last_byte, 32);
    }

    #[test]
    fn test_digest_empty() {
        let test_vector: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ];

        let mut gen = Sha256Gen::new();

        let result = gen.digest();

        assert_eq!(result.len(), 32);

        assert_eq!(result, test_vector);
    }

    #[test]
    fn test_multi_update_vs_single_pass() {
        let mut gen_single = Sha256Gen::new();
        gen_single.update(&[97, 68]);
        let result_single = gen_single.digest();

        let mut gen_multi = Sha256Gen::new();
        gen_multi.update(&[97]);
        gen_multi.update(&[68]);
        let result_multi = gen_multi.digest();

        assert_eq!(result_single, result_multi);
    }

    #[test]
    fn test_update_twice_less_than_buffer() {
        let mut testee = Sha256Gen::new();

        let data1 = [6u8];
        let data2 = [9u8];

        testee.update(&data1);
        testee.update(&data2);

        assert_eq!(testee.last_block_length, 2);
        assert_eq!(testee.last_block[..2], [6u8, 9u8]);
    }

    #[test]
    fn test_update_twice_bigger_than_buffer() {
        let mut testee = Sha256Gen::new();

        let data1 = [6u8; 65];
        let data2 = [9u8];

        testee.update(&data1);

        assert_eq!(testee.last_block_length, 1);
        assert_eq!(testee.last_block[..1], [6u8]);

        testee.update(&data2);

        assert_eq!(testee.last_block_length, 2);
        assert_eq!(testee.last_block[..2], [6u8, 9u8]);
    }

    #[test]
    fn test_update_twice_buffer_empty() {
        let mut testee = Sha256Gen::new();

        let data1 = [6u8; 63];
        let data2 = [9u8];

        testee.update(&data1);
        testee.update(&data2);

        assert_eq!(testee.last_block_length, 0);
    }
}