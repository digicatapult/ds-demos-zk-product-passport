import random
import subprocess
from gooey import Gooey, GooeyParser

@Gooey(program_name="Product Passport Signer")
def main():
    parser = GooeyParser(description="Sign a product passport")

    licence_group = parser.add_argument_group(
        "ACME Mining Company signing key", 
        ""
    )
    licence_group.add_argument('mining_company_sk', widget="FileChooser", default="./test_data/mining_company_sk.jwk")

    licence_group = parser.add_argument_group(
        "Product passport details", 
        ""
    )
    licence_group.add_argument('product', help="Product", default="Lithium")
    licence_group.add_argument('issue_date', help="Valid from", default="2025-12-01T00:00:00Z")
    licence_group.add_argument('product_passport_file', widget="FileSaver", default="./product_passport.jwt")
    tmp_claims_file = "./product_passport_claims.json"

    args = parser.parse_args()

    output = subprocess.run([
        "./target/release/gen_claims_file",
        "--path-to-claims-file", tmp_claims_file,
        "--key-value-claim-pair", "shipment_id," + str(random.randint(0,10000000)),
        "--key-value-claim-pair", "issue_date," + args.issue_date,
        "--key-value-claim-pair", "product," + args.product],
        capture_output=True, text=True)

    if output.returncode != 0:
        print("An error occurred.")
        print(output.stderr)
        return

    output = subprocess.run(["./target/release/sign", "-s", args.mining_company_sk, '-c', tmp_claims_file, '-t', args.product_passport_file], capture_output=True, text=True)
    
    if output.returncode == 0:
        print("Done\n")
    else: 
        print("An error occurred.")
        print(output.stderr)

if __name__ == "__main__":
    main()
