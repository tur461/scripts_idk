#[path = "utils.rs"] mod utils;
// #[path = "crypt.rs"] mod crypt;

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::pbkdf2;

use std::{
    fs::File,
    io::{prelude::*, BufReader},
    num::NonZeroU32
};

use utils::Util;
// use crypt::Crypt;

const SEED_BYTE_SIZE: usize = 64;
// const SEED_BYTE_SIZE: usize = 32;
const BIP39_MAGIC_NUM: usize = 11;
const ENT_SZ_IDX: usize = 3; // default is 12 word mnemonic!
const ENT_SZ: [usize; 5] = [
    128,    // 12 word mnemonic 
    160,    // 15 ..
    192,    // 18 ..
    224,    // 21 ..
    256     // 24 ..
];

pub struct BIP39 {
    mnemonic: String,
    seed: String
}

impl BIP39 { 

    pub fn new() -> BIP39 {
        BIP39 {
            mnemonic: "".to_owned(),
            seed: "".to_owned(),
        }
    }
    
    fn _words_from_wordlist(path: &str) -> Vec<String> {
        let file = File::open(path).expect("no such file");
        let buf = BufReader::new(file);
        buf.lines()
            .map(|l| l.expect("Could not parse line"))
            .collect()
    }

    fn _get_normalised_ent(srand_str: &mut String) -> String {
        // we need to find sha256 of hex(entropy) not binary entropy string
        let hexed = Util::bin2hex(&srand_str.as_str());
        let checksum_bit_len = ENT_SZ[ENT_SZ_IDX] / 32; // from bip39
        // get sha256 of un-normalised entropy
        let mut hasher = Sha256::new();
        hasher.update(Util::hexstr2bytes(&hexed.as_str()));
        let result = hasher.finalize();
        // sha256 result is [u8] of 32 len -> 8x32 = 256 
        let result_first_byte_bin = Util::lpad(
            format!("{:b}", result[0]).as_str(), 
            8
        );
      
        // now append first checksum_bit_len number of bits 
        // from sha256 of entropy, to the entropy string itself
        // to make its length divisible of bip39 magic number 11!
        srand_str.push_str(&result_first_byte_bin[0..checksum_bit_len]);
        srand_str.to_string()
    }
    
    fn _get_entropy() -> String {
        let u32_parts = ENT_SZ[ENT_SZ_IDX] / 32;
        let mut srand_str = "".to_owned();
        for _i in 0..u32_parts {
            let rnd_u32 = OsRng.next_u32();
            let bin_u32 = format!("{:b}", rnd_u32);
            // ensure binary is of 32 bits length!
            let padded = Util::lpad(
                bin_u32.as_str(), 
                32
            );
            
            srand_str.push_str(padded.as_str());
        }
        srand_str = Self::_get_normalised_ent(&mut srand_str);
        srand_str
    }

    fn _map_entropy2indexes(ent_w_c: &str) -> Vec<usize> {
        ent_w_c.chars()
        .collect::<Vec<char>>()
        .chunks(BIP39_MAGIC_NUM)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .iter()
        .map(|s| Util::bin2int(s))
        .collect()
    }
        
    fn _generate_mnemonic(wordlist_path: &str) -> String {
        let words = Self::_words_from_wordlist(wordlist_path);
        let entropy_with_checksum = Self::_get_entropy();
        let mut mnemonic_words = Vec::<&str>::new();
        let word_indexes = Self::_map_entropy2indexes(entropy_with_checksum.as_str());
        for i in word_indexes {
            mnemonic_words.push(words[i].as_str());
        }
        mnemonic_words.join(" ")
    }

    pub fn generate_seed(& mut self, wordlist_path: &str) {
        let mut passphrase: String = "".to_owned();
        println!("Enter a passphrase for extra level of security (press return key for none)):");
        std::io::stdin().read_line(&mut passphrase).expect("some problem");
        self.mnemonic =  Self::_generate_mnemonic(wordlist_path);
        let mut salt = "mnemonic".to_owned();
        // ensure no \r\n chars, so trim!
        salt.push_str(&passphrase.as_str().trim());
        
        let mut output = [0u8; SEED_BYTE_SIZE];
        // let mut output = Crypt::pbkdf2_512(
        //     &self.mnemonic.as_str(), 
        //     &salt.as_str(), 
        //     2048, 
        //     SEED_BYTE_SIZE
        // );

        // working perfect!!
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512, 
            NonZeroU32::new(2048).unwrap(), 
            &salt.as_bytes(),
            self.mnemonic.as_bytes(), 
            &mut output
        );
        self.seed = hex::encode(output);
    }

    pub fn get_seed(&self) -> &str {
        self.seed.as_str()
    }

    pub fn get_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }
}
