use otp_std::{
    Algorithm::{self, Sha1, Sha256, Sha512},
    Base, Digits, OwnedBase, OwnedSecret, OwnedTotp, Period, Secret, Skew, Totp,
};

const SECRET_CHARS: &str = "1234567890";
const SECRET_BYTES: &[u8] = SECRET_CHARS.as_bytes();

fn build_secret_for(algorithm: Algorithm) -> OwnedSecret {
    let value = SECRET_BYTES
        .iter()
        .copied()
        .cycle()
        .take(algorithm.recommended_length())
        .collect();

    Secret::owned(value).unwrap()
}

fn build_base(secret: Secret<'_>, algorithm: Algorithm, digits: Digits) -> Base<'_> {
    Base::builder()
        .secret(secret)
        .algorithm(algorithm)
        .digits(digits)
        .build()
}

fn build_base_for(algorithm: Algorithm, digits: Digits) -> OwnedBase {
    build_base(build_secret_for(algorithm), algorithm, digits)
}

fn build_totp(base: Base<'_>, skew: Skew, period: Period) -> Totp<'_> {
    Totp::builder().base(base).skew(skew).period(period).build()
}

fn build_totp_for(algorithm: Algorithm, digits: Digits, skew: Skew, period: Period) -> OwnedTotp {
    build_totp(build_base_for(algorithm, digits), skew, period)
}

type Pair = (u64, u32);
type Pairs<const N: usize> = [Pair; N];

const HOTP_COUNT: usize = 10;
const HOTP_PAIRS: Pairs<HOTP_COUNT> = [
    (0, 755224),
    (1, 287082),
    (2, 359152),
    (3, 969429),
    (4, 338314),
    (5, 254676),
    (6, 287922),
    (7, 162583),
    (8, 399871),
    (9, 520489),
];

const HOTP_DIGITS: Digits = Digits::new_ok(6).unwrap();

#[test]
fn hotp() {
    let digits = HOTP_DIGITS;
    let pairs = HOTP_PAIRS;

    let base = build_base_for(Sha1, digits);

    for (input, code) in pairs {
        assert!(base.verify(input, code));
        assert!(base.verify_string(input, digits.string(code)));
    }
}

const TOTP_COUNT: usize = 6;

const TOTP_DIGITS: Digits = Digits::new_ok(8).unwrap();
const TOTP_SKEW: Skew = Skew::disabled();
const TOTP_PERIOD: Period = Period::new_ok(30).unwrap();

const TOTP_SHA1_PAIRS: Pairs<TOTP_COUNT> = [
    (59, 94287082),
    (1111111109, 07081804),
    (1111111111, 14050471),
    (1234567890, 89005924),
    (2000000000, 69279037),
    (20000000000, 65353130),
];

const TOTP_SHA256_PAIRS: Pairs<TOTP_COUNT> = [
    (59, 46119246),
    (1111111109, 68084774),
    (1111111111, 67062674),
    (1234567890, 91819424),
    (2000000000, 90698825),
    (20000000000, 77737706),
];

const TOTP_SHA512_PAIRS: Pairs<TOTP_COUNT> = [
    (59, 90693936),
    (1111111109, 25091201),
    (1111111111, 99943326),
    (1234567890, 93441116),
    (2000000000, 38618901),
    (20000000000, 47863826),
];

#[test]
fn totp_sha1() {
    let digits = TOTP_DIGITS;
    let skew = TOTP_SKEW;
    let period = TOTP_PERIOD;

    let pairs = TOTP_SHA1_PAIRS;

    let totp = build_totp_for(Sha1, digits, skew, period);

    for (time, code) in pairs {
        assert!(totp.verify_at(time, code));
        assert!(totp.verify_string_at(time, digits.string(code)));
    }
}

#[test]
fn totp_sha256() {
    let digits = TOTP_DIGITS;
    let skew = TOTP_SKEW;
    let period = TOTP_PERIOD;

    let pairs = TOTP_SHA256_PAIRS;

    let totp = build_totp_for(Sha256, digits, skew, period);

    for (time, code) in pairs {
        assert!(totp.verify_at(time, code));
        assert!(totp.verify_string_at(time, digits.string(code)));
    }
}

#[test]
fn totp_sha512() {
    let digits = TOTP_DIGITS;
    let skew = TOTP_SKEW;
    let period = TOTP_PERIOD;

    let pairs = TOTP_SHA512_PAIRS;

    let totp = build_totp_for(Sha512, digits, skew, period);

    for (time, code) in pairs {
        assert!(totp.verify_at(time, code));
        assert!(totp.verify_string_at(time, digits.string(code)));
    }
}
