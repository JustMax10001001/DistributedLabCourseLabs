#![allow(non_upper_case_globals)]

use std::ops::Not;

const h0: u32 = 0x6a09e667;
const h1: u32 = 0xbb67ae85;
const h2: u32 = 0x3c6ef372;
const h3: u32 = 0xa54ff53a;
const h4: u32 = 0x510e527f;
const h5: u32 = 0x9b05688c;
const h6: u32 = 0x1f83d9ab;
const h7: u32 = 0x5be0cd19;

const k: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

#[allow(non_snake_case)]
pub fn digest(bytes: &Vec<u8>) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    let mut H: [u32; 8] = [h0, h1, h2, h3, h4, h5, h6, h7];

    let L: u64 = (bytes.len() as u64) * 8;

    let paddedMessage = pad(bytes, L);

    for chunk in paddedMessage.chunks(16) {
        let mut w: [u32; 64] = [0; 64];

        for i in 0..64 {
            if i < 16 {
                w[i] = chunk[i];

                continue;
            }

            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^
                w[i - 15] >> 3;
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^
                w[i - 2] >> 10;

            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        for i in 0..64 {
            let S1 = (e.rotate_right(6)) ^ (e.rotate_right(11)) ^ (e.rotate_right(25));
            let ch = (e & f) ^ (e.not() & g);
            let t1 = h.wrapping_add(S1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let S0 = (a.rotate_right(2)) ^ (a.rotate_right(13)) ^ (a.rotate_right(22));
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = S0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        H[0] = H[0].wrapping_add(a);
        H[1] = H[1].wrapping_add(b);
        H[2] = H[2].wrapping_add(c);
        H[3] = H[3].wrapping_add(d);
        H[4] = H[4].wrapping_add(e);
        H[5] = H[5].wrapping_add(f);
        H[6] = H[6].wrapping_add(g);
        H[7] = H[7].wrapping_add(h);
    }

    for i in 0..32 {
        let j = i / 4;
        let offset = 3 - i % 4;

        hash[i] = ((H[j] >> (8 * offset)) & 0xff) as u8;
    }

    hash
}

#[allow(non_snake_case)]
fn pad(messageBytes: &Vec<u8>, L: u64) -> Vec<u32> {
    let totalBits = messageBytes.len() * 8;

    let mut paddingLength = 512 - totalBits % 512;

    if paddingLength < 65 {
        paddingLength += 512;
    }

    let chunkCount = (totalBits + paddingLength) / 32;

    let mut chunks = Vec::with_capacity(chunkCount);

    for quad in messageBytes.chunks(4) {
        let chunk = if quad.len() == 4 {
            ((quad[0] as u32) << 24) | ((quad[1] as u32) << 16) |
                ((quad[2] as u32) << 8) | (quad[3] as u32)
        } else {
            let mut shift = 24;
            let mut partialChunk = 0u32;
            for single in quad {
                partialChunk |= (*single as u32) << shift;

                shift -= 8;
            }

            partialChunk
        };

        chunks.push(chunk);
    }

    // pad last chunk
    let K = paddingLength - 65;

    match chunks.last_mut() {
        None => { chunks.push(1 << 31); }
        Some(lastChunk) => {
            if L % 32 == 0 {
                chunks.push(1 << 31);
            } else {
                *lastChunk |= 1u32 << (K % 32);
            }
        }
    }

    /*if L % 32 != 0 && let Some(lastChunk) = chunks.last_mut() {
        *lastChunk |= 1u32 << (K % 32);
    } else {
        chunks.push(1 << 31);
    }*/

    // add zero chunks
    let zeroChunks = K / 32;
    for _ in 0..zeroChunks {
        chunks.push(0)
    }

    // add L to the end
    let hL = (L >> 32) as u32;
    chunks.push(hL);

    let lL = (L & 0xFFFFFFFF) as u32;
    chunks.push(lL);

    //panic!("lol");

    chunks
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pad_empty() {
        let zero_vec: Vec<u8> = Vec::new();

        let result = crate::sha256::pad(&zero_vec, 0);
        assert_eq!(result.len(), 16)
    }

    #[test]
    fn test_pad_single_zero() {
        let zero_vec: Vec<u8> = vec![0];

        let result = crate::sha256::pad(&zero_vec, 8);

        assert_eq!(result.len(), 16);

        let first_dword = result.first().unwrap();     // test whether 1 is set properly
        assert_eq!(*first_dword, 0x00800000);

        let last_dword = result.last().unwrap();        // test whether low dword of L is set properly
        assert_eq!(*last_dword, 8);
    }

    #[test]
    fn test_pad_four_zeros() {
        let zero_vec: Vec<u8> = vec![0, 0, 0, 0];

        let result = crate::sha256::pad(&zero_vec, (zero_vec.len() * 8) as u64);

        assert_eq!(result.len(), 16);

        let second_dword = result[1];                    // test whether 1 is set properly
        assert_eq!(second_dword, 0x80000000);

        let last_dword = result.last().unwrap();        // test whether low dword of L is set properly
        assert_eq!(*last_dword, 32);
    }

    #[test]
    fn test_pad_four_values() {
        let zero_vec: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd];

        let result = crate::sha256::pad(&zero_vec, (zero_vec.len() * 8) as u64);

        assert_eq!(result.len(), 16);

        let first_dword = result.first().unwrap();     // test whether message is not corrupted
        assert_eq!(*first_dword, 0xaabbccdd);

        let second_dword = result[1];                    // test whether 1 is set properly
        assert_eq!(second_dword, 0x80000000);

        let last_dword = result.last().unwrap();        // test whether low dword of L is set properly
        assert_eq!(*last_dword, 32);
    }

    #[test]
    fn test_digest_a() {
        let data: Vec<u8> = vec![97];       // small letter a

        let result = crate::sha256::digest(&data);

        for byte in result {
            print!("{:x}", byte);
        }

        println!();

        assert_eq!(result.len(), 32);
    }
}