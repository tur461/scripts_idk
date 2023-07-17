
#[path = "utils.rs"] mod utils;

use utils::Util;
use hmac_sha256::HMAC as hmac256;
use hmac_sha512::HMAC as hmac512;

macro_rules! min {
    ($x: expr) => ($x);
    ($x: expr, $($z: expr),+) => (::std::cmp::min($x, min!($($z),*)));
}

pub struct Crypt {
    msg: String,
}

impl Crypt {
    pub fn new() -> Crypt {
        Crypt {
            msg: String::from("thank u for using my crypt lib"),
        }
    }

    pub fn hmac_sha256(key: &str, msg: &str) -> Vec<u8> {
        hmac256::mac(msg.as_bytes(), key.as_bytes()).to_vec()
    }

    pub fn hmac_sha512(key: &str, msg: &str) -> Vec<u8> {
        hmac512::mac(msg.as_bytes(), key.as_bytes()).to_vec()
    }

    pub fn pbkdf2_256(pass: &str, salt: &str, iteration_count: usize, dk_len: usize) -> Vec<u8> {
        let mut op = Vec::<u8>::new(); // 32
        let hlen: usize = 32; // # of bytes of op of hmac_sha256
        let md_size: usize = 32;
        let mut md1 = Vec::<u8>::new();
        let mut work = Vec::<u8>::new();
    
        let mut counter: u32 = 1; // long
        let mut generated_key_length: usize = 0;
        
        while generated_key_length < dk_len {
            
            // U1 ends up in md1 and work
            let mut c = [0u8; 4];
            c[0] = ((counter >> 24) & 0xff) as u8;
            c[1] = ((counter >> 16) & 0xff) as u8;
            c[2] = ((counter >> 8) & 0xff) as u8;
            c[3] = ((counter >> 0) & 0xff) as u8;
            
            let y = &hmac256::mac(pass.as_bytes(), &[&salt.as_bytes()[..], &c[..]].concat());
            // Util::memcpy(&mut md1, &y, md_size); // pass as msg, salt as key
            // Util::memcpy(&mut work, &md1, md_size);
            md1 = y.to_vec();
            work = y.to_vec();

            let mut ic: usize = 1;
            while ic < iteration_count {
                // U2 ends up in md1
                let x = hmac256::mac(pass.as_bytes(), &md1);
                //Util::memcpy(&mut md1, &x, md_size); // pass as msg, salt as key
                md1 = x.to_vec();
                // U1 xor U2
                let mut i: usize = 0;
                while i < md_size {
                    work[i] ^= md1[i];
                    i += 1;
                }
                ic += 1;
                // and so on until iteration_count
            }
            
            // Copy the generated bytes to the key
            let bytes_to_write: usize = min!(dk_len - generated_key_length, md_size);
            // Util::memcpy(output, work, bytes_to_write);
            
            let mut j: usize = 0;
            while j < bytes_to_write {
                op.push(work[j]);
                j += 1;
            }
            generated_key_length += bytes_to_write;
            counter += 1;
            println!("md1: {:?} work: {:?}", md1, work);
            println!("gen: {} dklen: {}", generated_key_length, dk_len);
        }
        op.to_vec()
    }

    pub fn pbkdf2_512(pass: &str, salt: &str, iteration_count: usize, dk_len: usize) -> Vec<u8> {
        let mut op = Vec::<u8>::new(); // 32
        let hlen: usize = 64; // # of bytes of op of hmac_sha256
        let md_size: usize = 64;
        let mut md1 = Vec::<u8>::new();
        let mut work = Vec::<u8>::new();
    
        let mut counter: u32 = 1; // long
        let mut generated_key_length: usize = 0;
        println!("pass: {:?} salt: {:?}", pass, salt.trim());
        while generated_key_length < dk_len {
            
            // U1 ends up in md1 and work
            let mut c = [0u8; 4];
            c[0] = (counter >> 24) as u8 & 0xff;
            c[1] = (counter >> 16) as u8 & 0xff;
            c[2] = (counter >> 8) as u8 & 0xff;
            c[3] = (counter >> 0) as u8 & 0xff;
            
            let y = &hmac512::mac(pass.as_bytes(), &[&salt.as_bytes()[..], &c[..]].concat());
            // Util::memcpy(&mut md1, &y, md_size); // pass as msg, salt as key
            // Util::memcpy(&mut work, &md1, md_size);
            md1 = y.to_vec();
            work = y.to_vec();

            let mut ic: usize = 1;
            while ic < iteration_count {
                // U2 ends up in md1
                let x = hmac512::mac(pass.as_bytes(), &md1);
                //Util::memcpy(&mut md1, &x, md_size); // pass as msg, salt as key
                md1 = x.to_vec();
                // U1 xor U2
                let mut i: usize = 0;
                while i < md_size {
                    work[i] ^= md1[i];
                    i += 1;
                }
                ic += 1;
                // and so on until iteration_count
            }
            // Copy the generated bytes to the key
            let bytes_to_write: usize = min!(dk_len - generated_key_length, md_size);
            println!("dklen: {} gen_k_len: {} mdsize: {} bytes: {}", dk_len, generated_key_length, md_size, bytes_to_write);
            // Util::memcpy(output, work, bytes_to_write);
            
            let mut j: usize = 0;
            while j < bytes_to_write {
                op.push(work[j]);
                j += 1;
            }
            generated_key_length += bytes_to_write;
            counter += 1;
            // println!("md1: {:?} work: {:?}", md1, work);
            println!("gen: {} dklen: {}", generated_key_length, dk_len);
        }
        op.to_vec()
    }
}