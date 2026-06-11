//! Proof-of-work captcha for the registration form.
//!
//! On GET the server issues a challenge (random string, expiry and argon2
//! parameters) which is stored in an authenticated-encrypted private cookie
//! and embedded in the page. The browser brute-forces a nonce such that
//! argon2id(password=nonce, salt=challenge) has at least `difficulty` leading
//! zero bits (see assets/captcha.js), while the server only needs a single
//! argon2 evaluation to verify.
//!
//! The argon2 variant (argon2id), version (0x13), output length (32) and
//! parallelism (1) are fixed and must stay in sync with assets/captcha.js;
//! all other parameters travel with the challenge itself.

use axum_extra::extract::{
    PrivateCookieJar,
    cookie::{Cookie, SameSite},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const CAPTCHA_COOKIE_NAME: &str = "captcha";

/// Size of the challenge string
const CHALLENGE_LEN: usize = 32;
/// Challanges expire after this many seconds, to limit the window for replay attacks
const VALIDITY_SECS: i64 = 300;
/// We don't accept large nonces to avoid attacks
const MAX_NONCE_LEN: usize = 64;
/// The length of the argon2 hash output, in bytes. Must match the `hashLen` in frontend js.
const HASH_LEN: usize = 32;

/// Tunable proof-of-work parameters, attached to each issued challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowParams {
    /// Argon2 memory cost in KiB.
    pub mem_kib: u32,
    /// Argon2 iteration count.
    pub time_cost: u32,
    /// Required number of leading zero bits in the hash output.
    pub difficulty: u8,
}

impl Default for PowParams {
    fn default() -> Self {
        Self {
            mem_kib: 8192,
            time_cost: 1,
            difficulty: 6,
        }
    }
}

impl PowParams {
    /// Reject configurations that would make server-side verification too
    /// expensive (each POST costs one argon2 evaluation with these parameters)
    /// or the client-side solve practically impossible.
    pub fn validate(&self) -> Result<(), eyre::Report> {
        if !(8..=262144).contains(&self.mem_kib) {
            eyre::bail!("captcha memory cost should be between 8 and 262144 KiB");
        }
        if !(1..=16).contains(&self.time_cost) {
            eyre::bail!("captcha time cost should be between 1 and 16");
        }
        if self.difficulty > 32 {
            eyre::bail!("captcha difficulty should be at most 32 bits");
        }
        Ok(())
    }
}

/// A proof-of-work challenge as issued to a visitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
    pub params: PowParams,
}

impl Challenge {
    fn generate(params: PowParams) -> Self {
        use rand::{Rng, distr::Alphanumeric};

        Self {
            challenge: rand::rng()
                .sample_iter(&Alphanumeric)
                .take(CHALLENGE_LEN)
                .map(char::from)
                .collect(),
            expires_at: Utc::now() + chrono::Duration::seconds(VALIDITY_SECS),
            params,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

fn captcha_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::from(CAPTCHA_COOKIE_NAME);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie
}

/// Generate a fresh challenge and store it in the (encrypted) cookie jar.
pub fn issue_challenge(jar: PrivateCookieJar, params: PowParams) -> (PrivateCookieJar, Challenge) {
    let challenge = Challenge::generate(params);
    let mut cookie = captcha_cookie();
    cookie.set_value(serde_json::to_string(&challenge).expect("challenge is serializable"));
    (jar.add(cookie), challenge)
}

/// Read and remove the challenge from the cookie jar, making it single use.
pub fn take_challenge(jar: PrivateCookieJar) -> (PrivateCookieJar, Option<Challenge>) {
    let challenge = jar
        .get(CAPTCHA_COOKIE_NAME)
        .and_then(|c| serde_json::from_str(c.value()).ok());
    (jar.remove(captcha_cookie()), challenge)
}

/// Check a submitted solution against a previously issued challenge. The
/// parameters always come from the challenge (i.e. the cookie), never from
/// client-supplied form data.
pub fn verify_solution(challenge: &Challenge, submitted_challenge: &str, nonce: &str) -> bool {
    if challenge.is_expired()
        || challenge.challenge != submitted_challenge
        || nonce.is_empty()
        || nonce.len() > MAX_NONCE_LEN
    {
        return false;
    }

    let Some(hash) = pow_hash(nonce, &challenge.challenge, &challenge.params) else {
        return false;
    };
    leading_zero_bits(&hash) >= u32::from(challenge.params.difficulty)
}

fn pow_hash(nonce: &str, challenge: &str, params: &PowParams) -> Option<[u8; HASH_LEN]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(params.mem_kib, params.time_cost, 1, Some(HASH_LEN)).ok()?;
    let mut out = [0u8; HASH_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(nonce.as_bytes(), challenge.as_bytes(), &mut out)
        .ok()?;
    Some(out)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in bytes {
        let zeros = byte.leading_zeros();
        bits += zeros;
        if zeros < 8 {
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::cookie::Key;

    /// Cheap parameters to keep brute forcing in tests fast.
    fn test_params(difficulty: u8) -> PowParams {
        PowParams {
            mem_kib: 8,
            time_cost: 1,
            difficulty,
        }
    }

    fn solve(challenge: &Challenge) -> String {
        (0u32..)
            .map(|n| n.to_string())
            .find(|nonce| verify_solution(challenge, &challenge.challenge, nonce))
            .unwrap()
    }

    #[test]
    fn challenge_cookie_roundtrip_is_single_use() {
        let jar = PrivateCookieJar::new(Key::generate());
        let (jar, challenge) = issue_challenge(jar, PowParams::default());
        assert_eq!(challenge.challenge.len(), CHALLENGE_LEN);

        let (jar, taken) = take_challenge(jar);
        assert_eq!(taken, Some(challenge));

        // the challenge was removed by the first take
        let (_, taken) = take_challenge(jar);
        assert_eq!(taken, None);
    }

    #[test]
    fn garbage_cookie_value_is_rejected() {
        let jar = PrivateCookieJar::new(Key::generate());
        let mut cookie = captcha_cookie();
        cookie.set_value("not a challenge");
        let (_, taken) = take_challenge(jar.add(cookie));
        assert_eq!(taken, None);
    }

    #[test]
    fn params_bounds_are_validated() {
        assert!(PowParams::default().validate().is_ok());
        assert!(test_params(0).validate().is_ok());

        let huge_mem = PowParams {
            mem_kib: 1024 * 1024,
            ..PowParams::default()
        };
        assert!(huge_mem.validate().is_err());

        let zero_time = PowParams {
            time_cost: 0,
            ..PowParams::default()
        };
        assert!(zero_time.validate().is_err());

        let too_difficult = PowParams {
            difficulty: 33,
            ..PowParams::default()
        };
        assert!(too_difficult.validate().is_err());
    }

    #[test]
    fn leading_zero_bits_counts_bits() {
        assert_eq!(leading_zero_bits(&[0xff, 0x00]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x07]), 13);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x00]), 24);
    }

    #[test]
    fn verify_rejects_invalid_solutions() {
        let challenge = Challenge::generate(test_params(0));

        // difficulty 0 accepts any non-empty nonce of reasonable length...
        assert!(verify_solution(&challenge, &challenge.challenge, "0"));

        // ...but not a mismatched challenge, an empty or oversized nonce
        assert!(!verify_solution(&challenge, "something else", "0"));
        assert!(!verify_solution(&challenge, &challenge.challenge, ""));
        assert!(!verify_solution(
            &challenge,
            &challenge.challenge,
            &"9".repeat(65)
        ));

        // and not an expired challenge
        let expired = Challenge {
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
            ..challenge
        };
        assert!(!verify_solution(&expired, &expired.challenge, "0"));
    }

    #[test]
    fn solving_meets_the_difficulty_target() {
        let challenge = Challenge::generate(test_params(4));
        let nonce = solve(&challenge);

        // the found nonce should not pass a much higher difficulty for the
        // same challenge, proving the zero bits check does its job
        let harder = Challenge {
            params: test_params(32),
            ..challenge
        };
        assert!(!verify_solution(&harder, &harder.challenge, &nonce));
    }
}
