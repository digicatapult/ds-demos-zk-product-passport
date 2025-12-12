use clap::Parser;
use jwt_core::CustomClaims;
use std::io::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, short, default_value = "./claims.json")]
    path_to_claims_file: String,

    // List of key/value pairs separated by commas
    #[arg(long, num_args = 1.., value_delimiter = ' ')]
    key_value_claim_pair: Option<Vec<String>>,

    // List of key/value pairs separated by commas separated by spaces
    // where the value is a file to be dumped into the claims file
    #[arg(long, num_args = 1.., value_delimiter = '+')]
    key_file_claim_pair: Option<Vec<String>>,
}

fn main() {
    let args = Args::parse();

    let mut claims = CustomClaims::new();

    for claim in args
        .key_value_claim_pair
        .expect("No claims provided!")
        .iter()
    {
        // Interpret the argument as a comma-separated key-value pair
        let key_value_pair: Vec<_> = claim.split(',').collect();
        if key_value_pair.len() < 2 {
            panic!("Failed on claim {}", key_value_pair[0]);
        }
        claims.add(key_value_pair[0].to_string(), key_value_pair[1].to_string());
    }

    if args.key_file_claim_pair.is_some() {
        for claim in args
            .key_file_claim_pair
            .expect("No claims provided!")
            .iter()
        {
            // Interpret the argument as a comma-separated key-value pair
            let key_value_pair: Vec<_> = claim.split(',').collect();
            let mut f = std::fs::File::open(key_value_pair[1])
                .expect(&format!("Could not find file {}", key_value_pair[1]));
            let mut file_content = "".to_string();
            let _ = f
                .read_to_string(&mut file_content)
                .expect("Could not read from file");
            claims.add(key_value_pair[0].to_string(), file_content);
        }
    }

    let claims_string = serde_json::to_string_pretty(&claims).unwrap();

    let mut f = std::fs::File::create(&args.path_to_claims_file).expect(&format!(
        "Could not create file {:?}",
        args.path_to_claims_file
    ));
    f.write_all(&claims_string.as_bytes())
        .expect("Could not write to file");
}
