use std::env;

/// The Initial Permutation (IP) table
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// The Final Permutation (FP) table
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/*Expansion table */
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/* Post S-Box permutation */
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const SBOX: [[u8; 64]; 8] = [
    [
        /* S1 */
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    /* S2 */
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        /* S3 */
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
        12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8,
        7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        /* S4 */
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        /* S5 */
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        /* S6 */
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        /* S7 */
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        /* S8 */
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];
/* Permuted Choice 1 Table */
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/* Permuted Choice 2 Table */
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/* Iteration Shift Array */
const ITERATION_SHIFT: [u8; 16] = [
    /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
];

// Example keys
const KEY1: u64 = 0x0123456789abcdef;
const KEY2: u64 = 0xfedcba9876543210;
const KEY3: u64 = 0x0f1e2d3c4b5a6978;

/// Perform a permutation on a 64-bit block using a given table
fn initial_permutation(input: u64) -> u64 {
    let mut permuted = 0;
    for i in 0..64 {
        permuted <<= 1;
        permuted |= input >> (64 - IP[i] as u64) & 1;
    }
    permuted
}

fn key_schedule(key: u64) -> [u64; 16] {
    let mut sub_keys = [0u64; 16];
    let mut c = 0u32;
    let mut d = 0u32;

    // Permuted choice 1
    let mut permuted_choice_1 = 0u64;
    for i in 0..56 {
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= key >> (64 - PC1[i] as u64) & 1;
    }

    c = ((permuted_choice_1 >> 28) & 0x0FFFFFFF) as u32;
    d = (permuted_choice_1 & 0x0FFFFFFF) as u32;

    // Generate 16 subkeys
    for i in 0..16 {
        // Perform left shifts
        for _ in 0..ITERATION_SHIFT[i] {
            c = (c << 1 | c >> 27) & 0x0FFFFFFF;
            d = (d << 1 | d >> 27) & 0x0FFFFFFF;
        }

        // Combine C and D and permute with PC2
        let permuted_choice_2 = ((c as u64) << 28) | d as u64;
        sub_keys[i] = 0;
        for j in 0..48 {
            sub_keys[i] <<= 1;
            sub_keys[i] |= permuted_choice_2 >> (56 - PC2[j] as u64) & 1;
        }
    }
    sub_keys
}

fn f_function(r: u32, sub_key: u64) -> u32 {
    let mut s_input = 0u64;

    // Expansion
    for i in 0..48 {
        s_input <<= 1;
        s_input |= (r >> (32 - E[i] as u32) & 1) as u64;
    }

    // XOR with subkey
    s_input ^= sub_key;

    // S-box substitution
    let mut s_output = 0u32;
    for j in 0..8 {
        let row = ((s_input & (0x20 << (6 * (7 - j)))) >> (42 - 6 * j)) as u8 & 0x21;
        let col = ((s_input & (0x1E << (6 * (7 - j)))) >> (43 - 6 * j)) as u8 & 0x1F;
        s_output <<= 4;
        s_output |= SBOX[j][(row << 4 | col) as usize] as u32;
    }

    // Permutation
    let mut f_output = 0u32;
    for i in 0..32 {
        f_output <<= 1;
        f_output |= s_output >> (32 - P[i] as u32) & 1;
    }
    f_output
}

fn inverse_initial_permutation(input: u64) -> u64 {
    let mut permuted = 0u64;
    for i in 0..64 {
        permuted <<= 1;
        permuted |= input >> (64 - FP[i] as u64) & 1;
    }
    permuted
}

pub fn des(input: u64, key: u64, mode: char) -> u64 {
    let mut l: u32;
    let mut r: u32;
    let mut temp: u32;

    let sub_keys = key_schedule(key);

    // Initial permutation
    let init_perm_res = initial_permutation(input);
    l = (init_perm_res >> 32) as u32;
    r = init_perm_res as u32;

    // 16 rounds of DES
    for i in 0..16 {
        let f_res = f_function(
            r,
            if mode == 'd' {
                sub_keys[15 - i]
            } else {
                sub_keys[i]
            },
        );
        temp = r;
        r = l ^ f_res;
        l = temp;
    }

    // Combine halves and apply the final permutation
    let pre_output = ((r as u64) << 32) | l as u64;
    inverse_initial_permutation(pre_output)
}

/// TripleDES Encryption
/// Encrypts a 64-bit block using 3DES with three keys
fn triple_des_encrypt(block: u64, key1: u64, key2: u64, key3: u64) -> u64 {
    let step1 = des(block, key1, 'e');
    let step2 = des(step1, key2, 'e');
    let step3 = des(step2, key3, 'e');
    step3
}

/// TripleDES Decryption
/// Decrypts a 64-bit block using 3DES with three keys
fn triple_des_decrypt(block: u64, key1: u64, key2: u64, key3: u64) -> u64 {
    let step1 = des(block, key3, 'd');
    let step2 = des(step1, key2, 'd');
    let step3 = des(step2, key1, 'd');
    step3
}

/// Pads the input to a multiple of 8 bytes (64 bits)
fn pad_string(input: &str) -> Vec<u8> {
    let mut bytes = input.as_bytes().to_vec();
    let padding = 8 - (bytes.len() % 8);
    bytes.extend(vec![padding as u8; padding]);
    bytes
}

/// Converts a slice of 8 bytes into a u64
fn bytes_to_u64(block: &[u8]) -> u64 {
    let mut result = 0u64;
    for &byte in block {
        result = (result << 8) | (byte as u64);
    }
    result
}

/// Converts a u64 back into a Vec<u8>
fn u64_to_bytes(value: u64) -> Vec<u8> {
    (0..8)
        .rev()
        .map(|i| ((value >> (i * 8)) & 0xFF) as u8)
        .collect()
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ./tripledes <string>");
        return;
    }

    let input = &args[1];
    let padded_input = pad_string(input);

    // Encrypt the input
    let mut encrypted_blocks = Vec::new();
    for chunk in padded_input.chunks(8) {
        let block = bytes_to_u64(chunk);
        let encrypted_block = triple_des_encrypt(block, KEY1, KEY2, KEY3);
        encrypted_blocks.push(encrypted_block);
    }

    /*
    // Convert encrypted blocks to hexadecimal for display
    let encrypted_hex: Vec<String> = encrypted_blocks
        .iter()
        .map(|block| format!("{:016x}", block))
        .collect();
    //println!("{}", encrypted_hex.join(" "));
    //println!("");
    */

    // Decrypt the encrypted data
    let mut decrypted_bytes = Vec::new();
    for block in encrypted_blocks {
        let decrypted_block = triple_des_decrypt(block, KEY1, KEY2, KEY3);
        decrypted_bytes.extend(u64_to_bytes(decrypted_block));
    }

    // Remove padding
    if let Some(&padding) = decrypted_bytes.last() {
        decrypted_bytes.truncate(decrypted_bytes.len() - padding as usize);
    }

    //let decrypted_string = String::from_utf8(decrypted_bytes).expect("Invalid UTF-8");
    //println!("{}", decrypted_string);
}
