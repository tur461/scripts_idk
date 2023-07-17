
use sha2::{Sha256, Digest};

pub struct Util {}
impl Util {
    pub fn bin2int(bin: &str) -> usize {
        let mut num: usize = 0;
        let mut i = 0;
        let bits = bin.chars().rev().collect::<String>();
        for b in bits.chars() {
            num = num + (usize::pow(2, i) * b.to_string().parse::<usize>().unwrap());
            i += 1
        }
        num
    }
    
    pub fn bin2hex(s: &str) -> String {
        let len = s.len();
        let mut hexed: String = "".to_owned();
        for i in (0..len).step_by(4) {
            let x = Self::bin2int(&s[i..i+4]);
            match x {
                10 => hexed.push_str("a"),
                11 => hexed.push_str("b"),
                12 => hexed.push_str("c"),
                13 => hexed.push_str("d"),
                14 => hexed.push_str("e"),
                15 => hexed.push_str("f"),
                0|1|2|3|4|5|6|7|8|9 => hexed.push_str(format!("{}", x).as_str()),
                _ => (),
            };
        }
        hexed
    }
    
    pub fn hex2bin(s: &str, bin_len: usize) -> String {
        let len = s.len();
        let mut bined: String = "".to_owned();
        for i in (0..len).step_by(2) {
            let slic = &s[i..i+2];
            let bin = format!("{:b}", Self::bin2int(slic));
            let padded = Self::lpad(bin.as_str(), bin_len);
            // println!("slice: {}\nbin: {}\npadded: {}", slic, bin, padded);
            bined.push_str(padded.as_str());
        }
        println!("\nbined: {}\ns: {}", bined, s);
        bined
    }
    
    pub fn hexstr2bytes(s: &str) -> Vec<u8> {
        let len = s.len();
        let mut bytes: Vec<u8> = Vec::<u8>::new();
        for i in (0..len).step_by(2) {
            let slic = &s[i..i+2];
            let ss = u8::from_str_radix(slic, 16).unwrap();
            bytes.push(ss);
        }
        bytes
    }
    
    pub fn lpad(s: &str, final_len: usize) -> String {
        let mut l = s.len();
        let mut final_str = "".to_owned();
        if l < final_len {
            l = final_len - l;
            for _i in 0..l {
                final_str.push_str("0");
            }
        } else if l > final_len {
            final_str.push_str(&s[0..final_len]);
        }
        final_str.push_str(s);
        return final_str;
    }
    
    pub fn rpad(s: &str, final_len: usize) -> String {
        let mut l = s.len();
        let mut final_str = s.to_owned();
        if l < final_len {
            l = final_len - l;
            for _i in 0..l {
                final_str.push_str("0");
            }
        }
        final_str
    }
    
    pub fn rpad_bytes(byts: &mut Vec<u8>, final_len: usize) -> Vec<u8> {
        let mut l = byts.len();
        if l < final_len {
            l = final_len - l;
            for _i in 0..l {
                byts.push(0 as u8);
            }
        }
        byts.to_vec()
    }

    pub fn hash_sha256(byts: Vec<u8>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(byts);
        format!("{:x}", hasher.finalize())
    }

    pub fn memcpy(dest: &mut Vec<u8>, src: &[u8], size: usize) {
        let mut i = 0 as usize;
        while i < size {
            dest.push(src[i]);
            i += 1;
        }
    }
}