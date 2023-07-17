#[path = "utils.rs"] mod utils;

use std::collections::HashMap;
use hmac_sha512::HMAC as hmac512;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use utils::Util;

const MAC_KEY: &str = "Bitcoin seed";
const _2_POW_31: u32 = 2147483648;
const _2_POW_32: u32 = u32::MAX;


struct Root_Key_Meta {
    version: HashMap<String, Vec<u8>>,
    depth_byte: Vec<u8>,
    parent_fingerprint: Vec<u8>,
    child_number_bytes: Vec<u8>,
    master_chain_code_bytes: Vec<u8>,
    master_pvt_key_bytes: Vec<u8>,
}

impl Root_Key_Meta {
    pub fn new() -> Root_Key_Meta {
        let mut root_meta = Root_Key_Meta {
            version: HashMap::new(),
            depth_byte: [0u8; 1].to_vec(),
            parent_fingerprint: [0u8; 4].to_vec(),
            child_number_bytes: [0u8; 4].to_vec(),
            master_chain_code_bytes: [0u8; 32].to_vec(),
            master_pvt_key_bytes: [0u8; 33].to_vec(),
        };
        root_meta.version.insert("MAIN_PUB".to_owned(), Util::hexstr2bytes("0488b21e"));
        root_meta.version.insert("MAIN_PVT".to_owned(), Util::hexstr2bytes("0488ade4"));
        root_meta.version.insert("TEST_PUB".to_owned(), Util::hexstr2bytes("043587cf"));
        root_meta.version.insert("TEST_PVT".to_owned(), Util::hexstr2bytes("04358394"));

        root_meta
    }
    
    // root key is xtended private key (xprv...)
    pub fn get_root_key(
        &mut self, 
        master_pvt_key_l: &[u8], 
        master_chain_code_r: &[u8]
    ) -> String {
        self.master_chain_code_bytes = master_chain_code_r[..].to_vec();
        self.master_pvt_key_bytes = [&[0u8; 1][..], &master_pvt_key_l[..]].concat();
        let joined = [
            &self.version.get("MAIN_PVT").unwrap()[..],
            &self.depth_byte[..],
            &self.parent_fingerprint[..],
            &self.child_number_bytes[..],
            &self.master_chain_code_bytes[..],
            &self.master_pvt_key_bytes[..]
        ].concat();
        // BIP32 spec says!
        bs58::encode(joined).with_check().into_string()
    }
}

#[derive(Debug, Clone)]
pub struct _p {
    num: u32, 
    is_hard: bool
}
impl _p {
    pub fn new(num: u32, is_hard: bool) -> _p {
        _p { num, is_hard }
    }
    pub fn inc(&mut self) {
        if self.num == u32::MAX {
            return;
        }
        self.num += 1;
    }
    pub fn dec(&mut self) {
        if self.num == 0 {
            return;
        }
        self.num -= 1;
    }
    pub fn harden(&mut self) {
        self.is_hard = true;
        self.num += _2_POW_31;
    }
    pub fn is_hard(&self) -> bool {
        self.is_hard
    }
}

pub struct BIP44 {
    root_key: String,
    root_meta: Root_Key_Meta,
    derivation_path: [_p; 5], // 44'/60'/0'/0/0
}

impl BIP44 {
    pub fn new() -> BIP44 {
        BIP44 {
            root_key: "".to_owned(),
            root_meta: Root_Key_Meta::new(),
            derivation_path: [
                _p::new( 44, true),
                _p::new( 60, true),
                _p::new( 0, true),
                _p::new( 0, false),
                _p::new( 0, false)
            ]
        }
    }

    fn _curve_point_from_pvt_key(master_pvt_key: &str) -> String {
        let ctx = Secp256k1::new();
        let secret_key = SecretKey::from_slice(
            &hex::decode(master_pvt_key
        ).unwrap());
        let pub_key = PublicKey::from_secret_key(
            &ctx, 
            &secret_key.unwrap()
        );
        pub_key.to_string()
    }
    
    // BIP32 spec says!
    fn _get_parent_fingerprint() -> Vec<u8> {
        "not implemented yet!".as_bytes().to_vec()
    }

    pub fn generate_root_key_from_seed(&mut self, seed: &str) {
        let mac512 = hmac512::mac(
            Util::hexstr2bytes(seed), 
            MAC_KEY.as_bytes()
        );
        let master_pvt_key_l = mac512[0..32].to_vec();
        let master_chain_code_r = mac512[32..].to_vec();
        self.root_key = self.root_meta.get_root_key(
            &master_pvt_key_l, 
            &master_chain_code_r
        );
    } 

    pub fn xtended_child_pvt_key() {

    }

    pub fn get_root_key(&self) -> String {
        self.root_key.to_string()
    }

    pub fn get_derv_path(&self) -> Vec<_p> {
        self.derivation_path.to_vec()
    }
}