mod bip39;
mod bip44;

use dotenv::dotenv;
use bip39::BIP39;
use bip44::BIP44;
// struct BIP32 {
// }


fn main() {
    dotenv().ok();
    let mut bip_39: BIP39 = BIP39::new();
    let path = std::env::var("EN_WORDLIST_PATH").unwrap();
    println!("generating mnemonic {}", path);
    bip_39.generate_seed(path.as_str());
    println!("\nmnemonic: {}\nseed: {:}\nseed len: {} bytes", bip_39.get_mnemonic(), bip_39.get_seed(), bip_39.get_seed().len()/2);
    let mut bip_44 = BIP44::new();
    bip_44.generate_root_key_from_seed(bip_39.get_seed());
    println!("root key: {:?}", bip_44.get_root_key());
    let mut dp = bip_44.get_derv_path();
    dp[0].harden();
    dp[1].dec();
    dp[3].inc();
    dp[2].harden();
    dp[2].inc();
    println!("derv path: {:?}", dp);
    // println!("max: {:?}", u128::MAX);
}
