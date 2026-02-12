# Supply Chain Proof Demo
This demo is a modified version of the risc0 example for JWT verification from
the main RISC Zero repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

## Scenario
The demo provides a proof of concept of a 'zero-knowledge product passport',
which allows, say, a distributor to prove the provenance of their product
(specifically, that it did not originate in a conflict area) without revealing
precise details about who the supplier was.

## Installation
- Install [rust](https://rust-lang.org/tools/install) and
[RISC0](https://dev.risczero.com/api/zkvm/install), and then run `cargo build
  --release` in the repository root.
- Install dependencies for the frontend:
```bash
cd frontend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the demo
The process is as follows:
- Sign a mining licence
- Sign a product passport using the mining licence
- Prove fixed information about the mining licence
- Verify the proof

If the mining licence indicates that the company operates in a conflict zone
listed in the `conflict_zones.json` input file, they will not be able to
generate a zero-knowledge product passport that will be accepted by the
verifier.

Each operation can be performed using a GUI, e.g.:
```bash
cd frontend
source .venv/bin/activate
python sign_mining_licence.py
```

Test data is provided in the `./test_data` directory.  Here, you can modify the
set of conflict zones.

## Limitations
Note that due to limitations of the GUI library, the frontend does not display
properly when using dark mode on MacOS.