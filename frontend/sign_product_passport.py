import subprocess
from gooey import Gooey, GooeyParser

@Gooey(program_name="Product Passport Signer")
def main():
    parser = GooeyParser(description="Sign a product passport")

    licence_group = parser.add_argument_group(
        "ACME Mining Company signing key", 
        ""
    )
    licence_group.add_argument('mining_company_sk', widget="FileChooser")

    licence_group = parser.add_argument_group(
        "Product passport details", 
        ""
    )
    licence_group.add_argument('product', help="Product", default="Lithium")
    licence_group.add_argument('issue_date', help="Valid from", default="2025-12-01T00:00:00Z")
    licence_group.add_argument('product_passport_file', widget="FileSaver")
    tmp_claims_file = "./product_passport_claims.json"

    args = parser.parse_args()

    command_output = subprocess.run(["../target/release/gen_product_passport_claims_file", "--path-to-claims-file", tmp_claims_file, "--issue-date", args.issue_date, "--product", args.product], capture_output=True, text=True)
    print(command_output)
    command_output = subprocess.run(["../target/release/gen", "-s", args.mining_company_sk, '-c', tmp_claims_file, '-t', args.product_passport_file], capture_output=True, text=True)
    print(command_output)

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
