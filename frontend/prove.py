import subprocess
import os
from gooey import Gooey, GooeyParser

@Gooey(program_name="Zero Knowledge Product Passport Generator")
def main():
    parser = GooeyParser(description="Generate a JWT")
    parser.add_argument('passport', help="Product passport", widget="FileChooser")
    parser.add_argument('licence', help="Mining licence", widget="FileChooser")
    parser.add_argument('verification_key', help="National mining authority verification key", widget="FileChooser")
    parser.add_argument('conflict_zones', help="Conflict zones file", widget="FileChooser")
    parser.add_argument('receipt_file', help="Receipt file", widget="FileSaver")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["../target/release/prove", "--passport-file-path", args.passport, '--licence-file-path', args.licence, '--path-to-mining-authority-pk', args.verification_key, '--conflict-zones-file-path', args.conflict_zones, '--receipt-file-path', args.receipt_file], env=env, capture_output=True, text=True)
    print(output)



if __name__ == "__main__":
    main()

    # # Generate product passport
    
    # ./target/release/gen -s ./host/national_mining_authority_sk.jwk -c ./host/licence_claims.json -t ./licence.jwt 

    # # Generate mining licence
    # ./target/release/gen -s ./host/mining_company_sk.jwk -c ./host/product_passport_claims.json -t ./passport.jwt

    # # Prove
    # ./target/release/prove -p ./passport.jwt -l ./licence.jwt -v ./host/national_mining_authority_pk.jwk -c ./host/conflict_zones.json

    # # Verify
    # ./target/release/verify ./receipt.bin 
