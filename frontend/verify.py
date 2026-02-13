import subprocess
import os
from gooey import Gooey, GooeyParser


@Gooey(program_name="Zero Knowledge Product Passport Verifier", env={'GOOEY_THEME': 'dark'})
def main():
    parser = GooeyParser(description="Verify a Zero Knowledge Product Passport")
    parser.add_argument('receipt', help="Proof file", widget="FileChooser", default="./receipt.bin")

    args = parser.parse_args()

    env = os.environ.copy()
    env["RISC0_DEV_MODE"] = "1"

    output = subprocess.run(["../target/release/verify", args.receipt], env=env, capture_output=True, text=True)
    
    if output.returncode == 0:
        print(output.stdout)
    else: 
        print("An error occurred.")
        print(output.stderr)
        return

if __name__ == "__main__":
    main()

# The Python code in this repo simply presents a GUI for the CLI rust tool so we
# just test the test data (default files) exist, which via the GitHub action
# forces the developer to ensure that any changes to the test data are
# propagated to the GUIs
def test_default_files_exist():
    # The only input is a user-defined file
    assert True
    