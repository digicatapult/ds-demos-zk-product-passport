use host::compute_fingerprint;
use std::{fs::File, io::Read};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        panic!("Usage: get_fingerprint /path/to/key.jwk");
    }

    let mut f = File::open(&args[1]).expect("Could not find public key file");
    let mut pk = String::new();
    f.read_to_string(&mut pk)
        .expect("Could not parse public key from file");

    println!("{}", compute_fingerprint(pk));
}
