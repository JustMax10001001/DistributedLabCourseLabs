mod sha256;

use num_bigint::{BigInt, Sign};

fn main() {
    println!("Hello, world!");

    let a = BigInt::new(Sign::Plus, vec![0xEE, 0xFF000000, 0xAA0000BB]);
    let b = a << 4u8;

    println!("{}", b.to_str_radix(16));
}
