// This file has been modified from
// https://github.com/risc0/risc0/blob/main/examples/jwt-validator/src/lib.rs
// which has the following licence

// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::prelude::*;
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ELF;
use risc0_zkvm::sha::rust_crypto::Sha256;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;

#[derive(Serialize)]
struct FingerprintableJwk {
    e: String,
    kty: String,
    n: String,
}

pub fn compute_fingerprint(pk: String) -> String {
    let public_key: Value = serde_json::from_str(&pk).expect("Could not parse key");

    let e = public_key
        .get("e")
        .expect("Could not find mandatory field 'e'")
        .to_string()
        .replace("\"", "");

    let kty = public_key
        .get("kty")
        .expect("Could not find mandatory field 'kty'")
        .to_string()
        .replace("\"", "");

    let n = public_key
        .get("n")
        .expect("Could not find mandatory field 'n'")
        .to_string()
        .replace("\"", "");

    let fingerprintable_jwk = FingerprintableJwk { e, kty, n };

    let fingerprintable_jwk_as_str = serde_json::to_string(&fingerprintable_jwk).unwrap();

    let digest = Sha256::digest(fingerprintable_jwk_as_str);

    BASE64_URL_SAFE.encode(digest).replace("=", "")
}

pub fn prove_token_validation(
    passport: String,
    licence: String,
    pk: String,
    conflict_zones: String,
) -> (Receipt, String) {
    // Write the JWT
    let mut binding = ExecutorEnv::builder();
    let env = binding
        .write(&passport)
        .expect("failed to write product passport to env");
    env.write(&licence)
        .expect("failed to write mining licence to env");
    env.write(&pk)
        .expect("failed to write mining authority key to env");
    env.write(&conflict_zones)
        .expect("failed to write conflict zones to env");
    let env = env.build().expect("failed to build env");

    let prover = default_prover();

    let receipt = prover
        .prove(env, VERIFY_TOKEN_WITH_SOME_KEY_ELF)
        .expect("failed to prove")
        .receipt;

    /*let output: String = receipt
    .journal
    .decode()
    .expect("Journal should decode to string.");*/
    let output = "".to_string();

    (receipt, output)
}

#[cfg(test)]
mod test {

    use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;

    use super::*;

    const MINING_COMPANY_PK: &str = r#"{
    "alg": "RS256",
    "e": "AQAB",
    "key_ops": [
        "verify"
    ],
    "kty": "RSA",
    "n": "zcQwXx3EevOSkfH0VSWqtfmWTL4c2oIzW6u83qKO1W7XjLgTqpryL5vNCaxbVTkpU-GZctit0n6kj570tfny_sy6pb2q9wlvFBmDVyD-nL5oNjP5s3qEfvy15Bl9vMGFf3zycqMaVg_7VRVwK5d8QzpnVC0AGT10QdHnyGCadfPJqazTuVRp1f3ecK7bg7596sgVb8d9Wpaz2XPykQPfphsEb40vcp1tPN95-eRCgA24PwfUaKYHQQFMEQY_atJWbffyJ91zsBRy8fEQdfuQVZIRVQgO7FTsmLmQAHxR1dl2jP8B6zonWmtqWoMHoZfa-kmTPB4wNHa8EaLvtQ1060qYFmQWWumfNFnG7HNq2gTHt1cN1HCwstRGIaU_ZHubM_FKH_gLfJPKNW0KWML9mQQzf4AVov0Yfvk89WxY8ilSRx6KodJuIKKqwVh_58PJPLmBqszEfkTjtyxPwP8X8xRXfSz-vTU6vESCk3O6TRknoJkC2BJZ_ONQ0U5dxLcx",
    "use": "sig",
    "kid": "6ab0e8e4bc121fc287e35d3e5e0efb8a"
}"#;
    const NATIONAL_MINING_AUTHORITY_PK: &str = r#"{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "alg": "RS256",
    "n": "4B_DNuHWOWWD6wMyRihP6kGQyXdKeUVNAMuNpoXYHg1eLRJ0KJJMomD3MIjp3GpIPWck_gdnYQYEOPYdJN8FsS9VF3V_3gRaRD0As1DQeoMLKWSsC5_Ah7L_QXoj2BE-oKg1uyS8S5Qnq-bNsdNZ9idMtWN2Qk-43Wi8aN_6kYZ1Rb0oSr8ogi4CG0HtAYJajo3jFHvLRdTPfOLXVL6v_7Ta1uZJDQ0NBe_pPewGIURO8IVcdj7yF7xa1s90zSolUKq2xzfLV6pSOrI5X89gELmsEnRjKLMpp0lwenMUfpHITY3jmZYhqyikvLM_MGmw_OxuAclkOAS2xT4FmxE0Lw"
}"#;

    #[test]
    pub fn test_compute_fingerprint() {
        assert_eq!(
            compute_fingerprint(MINING_COMPANY_PK.to_string()),
            "US_g-NguIHYSNN95ZHMM0_gUI4iM9afv8KPyySaAnUQ".to_string()
        );
    }

    #[test]
    pub fn test_prove_token_validation() {
        let passport: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InNoaXBtZW50X2lkIiwidmFsdWUiOiI2NTMzMjEifSx7ImtleSI6Imlzc3VlX2RhdGUiLCJ2YWx1ZSI6IjIwMjUtMTItMDFUMDA6MDA6MDBaIn0seyJrZXkiOiJwcm9kdWN0IiwidmFsdWUiOiJMaXRoaXVtIn1dfQ.WphEqQT9DzJjNhPoYrRYlbNxEp2F3H0lvtmbP6uVNeMVMoV_2O0PwPFmnfNWaAdZ25XyoYN1hPGR050JSQ0ud-UD1_krAuKmMGP-iD1faaJjwiqs0BXJHNe6Zu_2CMindr8bhh6QrF0FSC1te97bAyjpmSai5IfT9D7jPQaqxl33-MWuWE__UsJztRLGrrP62G5fkyUL5m27Eirhdd99J4JHke0G7PjECM4um4DJ1eJs5OG7mMFEvoVJAnOlaMsLKKEsmjN-Xll2kwJHbmXblDH2A9AKl33ZafmbyMTHEEZD1lK_D-96cTi27ldCE3ERWvtoEhCE-PXCJPIMJ3OHFWbfQ_YCUHgB4QHYK4VYjEIiPLZ2kj7H_tX2Ly0wwQNZfWqtv5ozG88s8hmAsE3nY1z8_ngNuvIEtHAD7dkhj_UuvtW18LDN8RuOcZrB3lp0TaNq0CLjzH7cUJX6NqCIpIP9i_Al63wMfjm6iHnQPwNZndvneKmdWWkvyBAXguSI".to_string();
        let licence: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6Imlzc3Vlcl9pZCIsInZhbHVlIjoiTmF0aW9uYWxfTWluaW5nX0F1dGhvcml0eSJ9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQUNNRV9NaW5pbmdfQ29tcGFueSJ9LHsia2V5IjoiaXNzdWVfZGF0ZSIsInZhbHVlIjoiMjAyNS0wMS0wMVQwMDowMDowMFoifSx7ImtleSI6ImV4cGlyeV9kYXRlIiwidmFsdWUiOiIyMDM1LTAxLTAxVDAwOjAwOjAwWiJ9LHsia2V5IjoiY291bnRyeV9vZl9vcGVyYXRpb24iLCJ2YWx1ZSI6IkdCIn0seyJrZXkiOiJyZWdpb25fb2Zfb3BlcmF0aW9uIiwidmFsdWUiOiJDb3Jud2FsbCJ9LHsia2V5Ijoic3ViamVjdF9wayIsInZhbHVlIjoie1xuICAgIFwiYWxnXCI6IFwiUlMyNTZcIixcbiAgICBcImVcIjogXCJBUUFCXCIsXG4gICAgXCJrZXlfb3BzXCI6IFtcbiAgICAgICAgXCJ2ZXJpZnlcIlxuICAgIF0sXG4gICAgXCJrdHlcIjogXCJSU0FcIixcbiAgICBcIm5cIjogXCJ6Y1F3WHgzRWV2T1NrZkgwVlNXcXRmbVdUTDRjMm9Jelc2dTgzcUtPMVc3WGpMZ1RxcHJ5TDV2TkNheGJWVGtwVS1HWmN0aXQwbjZrajU3MHRmbnlfc3k2cGIycTl3bHZGQm1EVnlELW5MNW9OalA1czNxRWZ2eTE1Qmw5dk1HRmYzenljcU1hVmdfN1ZSVndLNWQ4UXpwblZDMEFHVDEwUWRIbnlHQ2FkZlBKcWF6VHVWUnAxZjNlY0s3Ymc3NTk2c2dWYjhkOVdwYXoyWFB5a1FQZnBoc0ViNDB2Y3AxdFBOOTUtZVJDZ0EyNFB3ZlVhS1lIUVFGTUVRWV9hdEpXYmZmeUo5MXpzQlJ5OGZFUWRmdVFWWklSVlFnTzdGVHNtTG1RQUh4UjFkbDJqUDhCNnpvbldtdHFXb01Ib1pmYS1rbVRQQjR3TkhhOEVhTHZ0UTEwNjBxWUZtUVdXdW1mTkZuRzdITnEyZ1RIdDFjTjFIQ3dzdFJHSWFVX1pIdWJNX0ZLSF9nTGZKUEtOVzBLV01MOW1RUXpmNEFWb3YwWWZ2azg5V3hZOGlsU1J4NktvZEp1SUtLcXdWaF81OFBKUExtQnFzekVma1RqdHl4UHdQOFg4eFJYZlN6LXZUVTZ2RVNDazNPNlRSa25vSmtDMkJKWl9PTlEwVTVkeExjeFwiLFxuICAgIFwidXNlXCI6IFwic2lnXCIsXG4gICAgXCJraWRcIjogXCI2YWIwZThlNGJjMTIxZmMyODdlMzVkM2U1ZTBlZmI4YVwiXG59In1dfQ.mCnNzGYkmBsiLjJ-4Mj3eQsbZXQXjsIAETadL2upPt-0s9C24jdjYjQ8MAzRL8RgLN7lIzxZf4KEbOeQag6f4DTkqPbiZVF5ROO-L9MTHj4MN5UHbNixKxMCe1HAdcggNmvl0AepcI-mI8-_mq2Ttz3jhliXytk30VHznhh6Gq5Lh_WhPXc0Jn9vNDxiRZ5nyvrDFHWMpUZkk4c3yUngNiscYcgQXiAxpg23huJbCBDQolq_MvrIY6fV9pT5MiDRN-eq1WC1Yj9vOGZqDUVvOwqi16G0OSof52fNiil8Ouwn2at8WnHWo_Gi5E99MZX23q50JLCGcvpj-ITH2mYcuw".to_string();
        let pk: String = NATIONAL_MINING_AUTHORITY_PK.to_string();
        let conflict_zones: String = r#"{
    "zones": [
        {
            "country": "GB",
            "region": "Warwickshire"
        },
        {
            "country": "GB",
            "region": "London"
        },
        {
            "country": "GB",
            "region": "Cheshire"
        },
        {
            "country": "GB",
            "region": "Buckinghamshire"
        },
        {
            "country": "GB",
            "region": "Northumberland"
        }
    ]
}"#
        .to_string();

        let (receipt, _) = prove_token_validation(passport, licence, pk, conflict_zones);
        assert!(receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_invalid_passport_sig() {
        let passport: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InNoaXBtZW50X2lkIiwidmFsdWUiOiI2NTMzMjEifSx7ImtleSI6Imlzc3VlX2RhdGUiLCJ2YWx1ZSI6IjIwMjUtMTItMDFUMDA6MDA6MDBaIn0seyJrZXkiOiJwcm9kdWN0IiwidmFsdWUiOiJMaXRoaXVtIn1dfQ.WphEqQT9DzJjNhPoYrRYlbNxEp2F3H0lvtmbP6uVNeMVMoV_2O0PwPFmnfNWaAdZ25XyoYN1hPGR050JSQ0ud-UD1_krAuKmMGP-iD1faaJjwiqs0BXJHNe6Zu_2CMindr8bhh6QrF0FSC1te97bAyjpmSai5IfT9D7jPQaqxl33-MWuWE__UsJztRLGrrP62G5fkyUL5m27Eirhdd99J4JHke0G7PjECM4um4DJ1eJs5OG7mMFEvoVJAnOlaMsLKKEsmjN-Xll2kwJHbmXblDH2A9AKl33ZafmbyMTHEEZD1lK_D-96cTi27ldCE3ERWvtoEhCE-PXCJPIMJ3OHFWbfQ_YCUHgB4QHYK4VYjEIiPLZ2kk7H_tX2Ly0wwQNZfWqtv5ozG88s8hmAsE3nY1z8_ngNuvIEtHAD7dkhj_UuvtW18LDN8RuOcZrB3lp0TaNq0CLjzH7cUJX6NqCIpIP9i_Al63wMfjm6iHnQPwNZndvneKmdWWkvyBAXguSI".to_string();
        let licence: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6Imlzc3Vlcl9pZCIsInZhbHVlIjoiTmF0aW9uYWxfTWluaW5nX0F1dGhvcml0eSJ9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQUNNRV9NaW5pbmdfQ29tcGFueSJ9LHsia2V5IjoiaXNzdWVfZGF0ZSIsInZhbHVlIjoiMjAyNS0wMS0wMVQwMDowMDowMFoifSx7ImtleSI6ImV4cGlyeV9kYXRlIiwidmFsdWUiOiIyMDM1LTAxLTAxVDAwOjAwOjAwWiJ9LHsia2V5IjoiY291bnRyeV9vZl9vcGVyYXRpb24iLCJ2YWx1ZSI6IkdCIn0seyJrZXkiOiJyZWdpb25fb2Zfb3BlcmF0aW9uIiwidmFsdWUiOiJDb3Jud2FsbCJ9LHsia2V5Ijoic3ViamVjdF9wayIsInZhbHVlIjoie1xuICAgIFwiYWxnXCI6IFwiUlMyNTZcIixcbiAgICBcImVcIjogXCJBUUFCXCIsXG4gICAgXCJrZXlfb3BzXCI6IFtcbiAgICAgICAgXCJ2ZXJpZnlcIlxuICAgIF0sXG4gICAgXCJrdHlcIjogXCJSU0FcIixcbiAgICBcIm5cIjogXCJ6Y1F3WHgzRWV2T1NrZkgwVlNXcXRmbVdUTDRjMm9Jelc2dTgzcUtPMVc3WGpMZ1RxcHJ5TDV2TkNheGJWVGtwVS1HWmN0aXQwbjZrajU3MHRmbnlfc3k2cGIycTl3bHZGQm1EVnlELW5MNW9OalA1czNxRWZ2eTE1Qmw5dk1HRmYzenljcU1hVmdfN1ZSVndLNWQ4UXpwblZDMEFHVDEwUWRIbnlHQ2FkZlBKcWF6VHVWUnAxZjNlY0s3Ymc3NTk2c2dWYjhkOVdwYXoyWFB5a1FQZnBoc0ViNDB2Y3AxdFBOOTUtZVJDZ0EyNFB3ZlVhS1lIUVFGTUVRWV9hdEpXYmZmeUo5MXpzQlJ5OGZFUWRmdVFWWklSVlFnTzdGVHNtTG1RQUh4UjFkbDJqUDhCNnpvbldtdHFXb01Ib1pmYS1rbVRQQjR3TkhhOEVhTHZ0UTEwNjBxWUZtUVdXdW1mTkZuRzdITnEyZ1RIdDFjTjFIQ3dzdFJHSWFVX1pIdWJNX0ZLSF9nTGZKUEtOVzBLV01MOW1RUXpmNEFWb3YwWWZ2azg5V3hZOGlsU1J4NktvZEp1SUtLcXdWaF81OFBKUExtQnFzekVma1RqdHl4UHdQOFg4eFJYZlN6LXZUVTZ2RVNDazNPNlRSa25vSmtDMkJKWl9PTlEwVTVkeExjeFwiLFxuICAgIFwidXNlXCI6IFwic2lnXCIsXG4gICAgXCJraWRcIjogXCI2YWIwZThlNGJjMTIxZmMyODdlMzVkM2U1ZTBlZmI4YVwiXG59In1dfQ.mCnNzGYkmBsiLjJ-4Mj3eQsbZXQXjsIAETadL2upPt-0s9C24jdjYjQ8MAzRL8RgLN7lIzxZf4KEbOeQag6f4DTkqPbiZVF5ROO-L9MTHj4MN5UHbNixKxMCe1HAdcggNmvl0AepcI-mI8-_mq2Ttz3jhliXytk30VHznhh6Gq5Lh_WhPXc0Jn9vNDxiRZ5nyvrDFHWMpUZkk4c3yUngNiscYcgQXiAxpg23huJbCBDQolq_MvrIY6fV9pT5MiDRN-eq1WC1Yj9vOGZqDUVvOwqi16G0OSof52fNiil8Ouwn2at8WnHWo_Gi5E99MZX23q50JLCGcvpj-ITH2mYcuw".to_string();
        let pk: String = NATIONAL_MINING_AUTHORITY_PK.to_string();
        let conflict_zones: String = r#"{
    "zones": [
        {
            "country": "GB",
            "region": "Warwickshire"
        },
        {
            "country": "GB",
            "region": "London"
        },
        {
            "country": "GB",
            "region": "Cheshire"
        },
        {
            "country": "GB",
            "region": "Buckinghamshire"
        },
        {
            "country": "GB",
            "region": "Northumberland"
        }
    ]
}"#
        .to_string();

        let (_, _) = prove_token_validation(passport, licence, pk, conflict_zones);
    }

    #[test]
    #[should_panic]
    fn test_invalid_licence_sig() {
        let passport: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InNoaXBtZW50X2lkIiwidmFsdWUiOiI2NTMzMjEifSx7ImtleSI6Imlzc3VlX2RhdGUiLCJ2YWx1ZSI6IjIwMjUtMTItMDFUMDA6MDA6MDBaIn0seyJrZXkiOiJwcm9kdWN0IiwidmFsdWUiOiJMaXRoaXVtIn1dfQ.WphEqQT9DzJjNhPoYrRYlbNxEp2F3H0lvtmbP6uVNeMVMoV_2O0PwPFmnfNWaAdZ25XyoYN1hPGR050JSQ0ud-UD1_krAuKmMGP-iD1faaJjwiqs0BXJHNe6Zu_2CMindr8bhh6QrF0FSC1te97bAyjpmSai5IfT9D7jPQaqxl33-MWuWE__UsJztRLGrrP62G5fkyUL5m27Eirhdd99J4JHke0G7PjECM4um4DJ1eJs5OG7mMFEvoVJAnOlaMsLKKEsmjN-Xll2kwJHbmXblDH2A9AKl33ZafmbyMTHEEZD1lK_D-96cTi27ldCE3ERWvtoEhCE-PXCJPIMJ3OHFWbfQ_YCUHgB4QHYK4VYjEIiPLZ2kk7H_tX2Ly0wwQNZfWqtv5ozG88s8hmAsE3nY1z8_ngNuvIEtHAD7dkhj_UuvtW18LDN8RuOcZrB3lp0TaNq0CLjzH7cUJX6NqCIpIP9i_Al63wMfjm6iHnQPwNZndvneKmdWWkvyBAXguSI".to_string();
        let licence: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6Imlzc3Vlcl9pZCIsInZhbHVlIjoiTmF0aW9uYWxfTWluaW5nX0F1dGhvcml0eSJ9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQUNNRV9NaW5pbmdfQ29tcGFueSJ9LHsia2V5IjoiaXNzdWVfZGF0ZSIsInZhbHVlIjoiMjAyNS0wMS0wMVQwMDowMDowMFoifSx7ImtleSI6ImV4cGlyeV9kYXRlIiwidmFsdWUiOiIyMDM1LTAxLTAxVDAwOjAwOjAwWiJ9LHsia2V5IjoiY291bnRyeV9vZl9vcGVyYXRpb24iLCJ2YWx1ZSI6IkdCIn0seyJrZXkiOiJyZWdpb25fb2Zfb3BlcmF0aW9uIiwidmFsdWUiOiJDb3Jud2FsbCJ9LHsia2V5Ijoic3ViamVjdF9wayIsInZhbHVlIjoie1xuICAgIFwiYWxnXCI6IFwiUlMyNTZcIixcbiAgICBcImVcIjogXCJBUUFCXCIsXG4gICAgXCJrZXlfb3BzXCI6IFtcbiAgICAgICAgXCJ2ZXJpZnlcIlxuICAgIF0sXG4gICAgXCJrdHlcIjogXCJSU0FcIixcbiAgICBcIm5cIjogXCJ6Y1F3WHgzRWV2T1NrZkgwVlNXcXRmbVdUTDRjMm9Jelc2dTgzcUtPMVc3WGpMZ1RxcHJ5TDV2TkNheGJWVGtwVS1HWmN0aXQwbjZrajU3MHRmbnlfc3k2cGIycTl3bHZGQm1EVnlELW5MNW9OalA1czNxRWZ2eTE1Qmw5dk1HRmYzenljcU1hVmdfN1ZSVndLNWQ4UXpwblZDMEFHVDEwUWRIbnlHQ2FkZlBKcWF6VHVWUnAxZjNlY0s3Ymc3NTk2c2dWYjhkOVdwYXoyWFB5a1FQZnBoc0ViNDB2Y3AxdFBOOTUtZVJDZ0EyNFB3ZlVhS1lIUVFGTUVRWV9hdEpXYmZmeUo5MXpzQlJ5OGZFUWRmdVFWWklSVlFnTzdGVHNtTG1RQUh4UjFkbDJqUDhCNnpvbldtdHFXb01Ib1pmYS1rbVRQQjR3TkhhOEVhTHZ0UTEwNjBxWUZtUVdXdW1mTkZuRzdITnEyZ1RIdDFjTjFIQ3dzdFJHSWFVX1pIdWJNX0ZLSF9nTGZKUEtOVzBLV01MOW1RUXpmNEFWb3YwWWZ2azg5V3hZOGlsU1J4NktvZEp1SUtLcXdWaF81OFBKUExtQnFzekVma1RqdHl4UHdQOFg4eFJYZlN6LXZUVTZ2RVNDazNPNlRSa25vSmtDMkJKWl9PTlEwVTVkeExjeFwiLFxuICAgIFwidXNlXCI6IFwic2lnXCIsXG4gICAgXCJraWRcIjogXCI2YWIwZThlNGJjMTIxZmMyODdlMzVkM2U1ZTBlZmI4YVwiXG59In1dfQ.mCnNzGYkmBsiLjJ-4Mj3eQsbZXQXjsIAETadL2upPt-0s9C24jdjYkQ8MAzRL8RgLN7lIzxZf4KEbOeQag6f4DTkqPbiZVF5ROO-L9MTHj4MN5UHbNixKxMCe1HAdcggNmvl0AepcI-mI8-_mq2Ttz3jhliXytk30VHznhh6Gq5Lh_WhPXc0Jn9vNDxiRZ5nyvrDFHWMpUZkk4c3yUngNiscYcgQXiAxpg23huJbCBDQolq_MvrIY6fV9pT5MiDRN-eq1WC1Yj9vOGZqDUVvOwqi16G0OSof52fNiil8Ouwn2at8WnHWo_Gi5E99MZX23q50JLCGcvpj-ITH2mYcuw".to_string();
        let pk: String = NATIONAL_MINING_AUTHORITY_PK.to_string();
        let conflict_zones: String = r#"{
    "zones": [
        {
            "country": "GB",
            "region": "Warwickshire"
        },
        {
            "country": "GB",
            "region": "London"
        },
        {
            "country": "GB",
            "region": "Cheshire"
        },
        {
            "country": "GB",
            "region": "Buckinghamshire"
        },
        {
            "country": "GB",
            "region": "Northumberland"
        }
    ]
}"#
        .to_string();

        let (_, _) = prove_token_validation(passport, licence, pk, conflict_zones);
    }

    #[test]
    #[should_panic]
    fn test_operating_in_conflict_zone() {
        let passport: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6InNoaXBtZW50X2lkIiwidmFsdWUiOiI2NTMzMjEifSx7ImtleSI6Imlzc3VlX2RhdGUiLCJ2YWx1ZSI6IjIwMjUtMTItMDFUMDA6MDA6MDBaIn0seyJrZXkiOiJwcm9kdWN0IiwidmFsdWUiOiJMaXRoaXVtIn1dfQ.WphEqQT9DzJjNhPoYrRYlbNxEp2F3H0lvtmbP6uVNeMVMoV_2O0PwPFmnfNWaAdZ25XyoYN1hPGR050JSQ0ud-UD1_krAuKmMGP-iD1faaJjwiqs0BXJHNe6Zu_2CMindr8bhh6QrF0FSC1te97bAyjpmSai5IfT9D7jPQaqxl33-MWuWE__UsJztRLGrrP62G5fkyUL5m27Eirhdd99J4JHke0G7PjECM4um4DJ1eJs5OG7mMFEvoVJAnOlaMsLKKEsmjN-Xll2kwJHbmXblDH2A9AKl33ZafmbyMTHEEZD1lK_D-96cTi27ldCE3ERWvtoEhCE-PXCJPIMJ3OHFWbfQ_YCUHgB4QHYK4VYjEIiPLZ2kk7H_tX2Ly0wwQNZfWqtv5ozG88s8hmAsE3nY1z8_ngNuvIEtHAD7dkhj_UuvtW18LDN8RuOcZrB3lp0TaNq0CLjzH7cUJX6NqCIpIP9i_Al63wMfjm6iHnQPwNZndvneKmdWWkvyBAXguSI".to_string();
        let licence: String = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbXMiOlt7ImtleSI6Imlzc3Vlcl9pZCIsInZhbHVlIjoiTmF0aW9uYWxfTWluaW5nX0F1dGhvcml0eSJ9LHsia2V5Ijoic3ViamVjdF9pZCIsInZhbHVlIjoiQUNNRV9NaW5pbmdfQ29tcGFueSJ9LHsia2V5IjoiaXNzdWVfZGF0ZSIsInZhbHVlIjoiMjAyNS0wMS0wMVQwMDowMDowMFoifSx7ImtleSI6ImV4cGlyeV9kYXRlIiwidmFsdWUiOiIyMDM1LTAxLTAxVDAwOjAwOjAwWiJ9LHsia2V5IjoiY291bnRyeV9vZl9vcGVyYXRpb24iLCJ2YWx1ZSI6IkdCIn0seyJrZXkiOiJyZWdpb25fb2Zfb3BlcmF0aW9uIiwidmFsdWUiOiJDb3Jud2FsbCJ9LHsia2V5Ijoic3ViamVjdF9wayIsInZhbHVlIjoie1xuICAgIFwiYWxnXCI6IFwiUlMyNTZcIixcbiAgICBcImVcIjogXCJBUUFCXCIsXG4gICAgXCJrZXlfb3BzXCI6IFtcbiAgICAgICAgXCJ2ZXJpZnlcIlxuICAgIF0sXG4gICAgXCJrdHlcIjogXCJSU0FcIixcbiAgICBcIm5cIjogXCJ6Y1F3WHgzRWV2T1NrZkgwVlNXcXRmbVdUTDRjMm9Jelc2dTgzcUtPMVc3WGpMZ1RxcHJ5TDV2TkNheGJWVGtwVS1HWmN0aXQwbjZrajU3MHRmbnlfc3k2cGIycTl3bHZGQm1EVnlELW5MNW9OalA1czNxRWZ2eTE1Qmw5dk1HRmYzenljcU1hVmdfN1ZSVndLNWQ4UXpwblZDMEFHVDEwUWRIbnlHQ2FkZlBKcWF6VHVWUnAxZjNlY0s3Ymc3NTk2c2dWYjhkOVdwYXoyWFB5a1FQZnBoc0ViNDB2Y3AxdFBOOTUtZVJDZ0EyNFB3ZlVhS1lIUVFGTUVRWV9hdEpXYmZmeUo5MXpzQlJ5OGZFUWRmdVFWWklSVlFnTzdGVHNtTG1RQUh4UjFkbDJqUDhCNnpvbldtdHFXb01Ib1pmYS1rbVRQQjR3TkhhOEVhTHZ0UTEwNjBxWUZtUVdXdW1mTkZuRzdITnEyZ1RIdDFjTjFIQ3dzdFJHSWFVX1pIdWJNX0ZLSF9nTGZKUEtOVzBLV01MOW1RUXpmNEFWb3YwWWZ2azg5V3hZOGlsU1J4NktvZEp1SUtLcXdWaF81OFBKUExtQnFzekVma1RqdHl4UHdQOFg4eFJYZlN6LXZUVTZ2RVNDazNPNlRSa25vSmtDMkJKWl9PTlEwVTVkeExjeFwiLFxuICAgIFwidXNlXCI6IFwic2lnXCIsXG4gICAgXCJraWRcIjogXCI2YWIwZThlNGJjMTIxZmMyODdlMzVkM2U1ZTBlZmI4YVwiXG59In1dfQ.mCnNzGYkmBsiLjJ-4Mj3eQsbZXQXjsIAETadL2upPt-0s9C24jdjYjQ8MAzRL8RgLN7lIzxZf4KEbOeQag6f4DTkqPbiZVF5ROO-L9MTHj4MN5UHbNixKxMCe1HAdcggNmvl0AepcI-mI8-_mq2Ttz3jhliXytk30VHznhh6Gq5Lh_WhPXc0Jn9vNDxiRZ5nyvrDFHWMpUZkk4c3yUngNiscYcgQXiAxpg23huJbCBDQolq_MvrIY6fV9pT5MiDRN-eq1WC1Yj9vOGZqDUVvOwqi16G0OSof52fNiil8Ouwn2at8WnHWo_Gi5E99MZX23q50JLCGcvpj-ITH2mYcuw".to_string();
        let pk: String = NATIONAL_MINING_AUTHORITY_PK.to_string();
        let conflict_zones: String = r#"{
    "zones": [
        {
            "country": "GB",
            "region": "Cheshire"
        },
        {
            "country": "GB",
            "region": "London"
        },
        {
            "country": "GB",
            "region": "Cornwall"
        },
        {
            "country": "GB",
            "region": "Buckinghamshire"
        },
        {
            "country": "GB",
            "region": "Northumberland"
        }
    ]
}"#
        .to_string();

        let (_, _) = prove_token_validation(passport, licence, pk, conflict_zones);
    }
}
