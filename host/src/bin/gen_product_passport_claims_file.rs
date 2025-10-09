use clap::Parser;
use jwt_core::CustomClaims;
use std::io::prelude::*;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "./product_passport_claims.json")]
    path_to_claims_file: String,

    #[arg(short, long, default_value = "2025-06-01T00:00:00Z")]
    issue_date: String,

    #[arg(short, long, default_value = "Lithium")]
    product: String,
}

fn main() {
    let args = Args::parse();

    let mut mining_certificate_claims = CustomClaims::new();
    mining_certificate_claims.add("issue_date".to_string(), args.issue_date.to_string(), false);
    mining_certificate_claims.add("product".to_string(), args.product.to_string(), false);
    mining_certificate_claims.add("shipment_id".to_string(), Uuid::new_v4().to_string(), false);

    let mining_certificate_claims_string =
        serde_json::to_string_pretty(&mining_certificate_claims).unwrap();

    let mut f =
        std::fs::File::create(&args.path_to_claims_file).expect("Could not create claims file");
    f.write_all(&mining_certificate_claims_string.as_bytes())
        .expect("Could not write to file");
}
