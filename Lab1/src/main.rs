mod sha256;

use crate::sha256::{Sha256Gen};

fn main() {
    println!("Hello, world!");

    let mut sha256 = Sha256Gen::new();

    let test_string = "Public-key cryptography is based on the intractability of certain mathematical problems. ";
    let test_string_2 = "Early public-key systems based their security on the assumption that it is difficult to factor a large integer composed of two or more large prime factors. For later elliptic-curve-based protocols, the base assumption is that finding the discrete logarithm of a random elliptic curve element with respect to a publicly known base point is infeasible: this is the \"elliptic curve discrete logarithm problem\" (ECDLP). The security of elliptic curve cryptography depends on the ability to compute a point multiplication and the inability to compute the multiplicand given the original and product points. The size of the elliptic curve, measured by the total number of discrete integer pairs satisfying the curve equation, determines the difficulty of the problem. The U.S. National Institute of Standards and Technology (NIST) has endorsed elliptic curve cryptography in its Suite B set of recommended algorithms, specifically elliptic-curve Diffie–Hellman (ECDH) for key exchange and Elliptic Curve Digital Signature Algorithm (ECDSA) for digital signature. The U.S. National Security Agency (NSA) allows their use for protecting information classified up to top secret with 384-bit keys.[2] However, in August 2015, the NSA announced that it plans to replace Suite B with a new cipher suite due to concerns about quantum computing attacks on ECC.[3]";
    //let test_string = "public-key cryptography is based on the intractability of certain mathematical problems";

    sha256.update(test_string.as_bytes());
    sha256.update(test_string_2.as_bytes());

    print_as_integer(&sha256.digest())
}

fn print_as_integer(bytes: &[u8]) {
    for byte in bytes {
        print!("{:x}", byte);
    }

    println!();
}
