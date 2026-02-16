import os

# The Python code in this repo simply presents a GUI for the CLI rust tool so we
# just test the test data (default files) exist, which via the GitHub action
# forces the developer to ensure that any changes to the test data are
# propagated to the GUIs

def test_sign_mining_licence():
    assert os.path.exists("./test_data/national_mining_authority_sk.jwk")
    assert os.path.exists("./test_data/mining_company_pk.jwk")

def test_sign_product_passport():
    assert os.path.exists("./test_data/mining_company_sk.jwk")

def test_prove():
    assert os.path.exists("./test_data/national_mining_authority_pk.jwk")
    assert os.path.exists("./test_data/conflict_zones.json")

def test_verify():
    # The only input is a user-defined file
    assert True