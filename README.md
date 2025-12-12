# Supply Chain Proof Demo

This demo is a modified version of the risc0 example for JWT verification from
the main RISC Zero repository
[https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs](https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/main.rs)

The demo provides a proof of concept of a 'zero-knowledge product passport',
which allows, say, a distributor to prove the provenance of their product
(specifically, that it did not originate in a conflict area) without revealing
precise details about who the supplier was.

We use RISC Zero to generate and verify zero-knowledge proofs and provide a GUI
frontend using the Python library Gooey.

## Table of Contents

- [Setup](#setup)
- [Getting Started](#getting-started)

## Setup
- Follow the Risc Zero installation steps and then build the rust binaries in
  the repo root:
```bash
cargo build
```
- Install dependencies for the frontend:
```bash
cd frontend
python -m venv .venv
pip install -r requirements.txt
```

## Getting Started
The process is as follows:
- Sign a mining licence
- Sign a product passport using the mining licence
- Prove fixed information about the mining licence
- Verify the proof

Each operation can be performed using a GUI:
```bash
cd frontend
source .venv/bin/activate
python sign_mining_licence.py
```

Test data is provided in the `./test_data` directory.

Note that due to limitations of the library, the frontend does not display
properly when using dark mode on MacOS.