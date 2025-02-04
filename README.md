# `otp-std`

[![License][License Badge]][License]
[![Version][Version Badge]][Crate]
[![Downloads][Downloads Badge]][Crate]
[![Test][Test Badge]][Actions]

> *Generating and checking one-time passwords.*

## Installation

### `cargo`

You can add `otp-std` as a dependency with the following command:

```console
$ cargo add otp-std
```

Or by directly specifying it in the configuration like so:

```toml
[dependencies]
otp-std = "0.1.1"
```

Alternatively, you can add it directly from the source:

```toml
[dependencies.otp-std]
git = "https://github.com/nekitdev/otp-std.git"
```

## Examples

For demonstration purposes, all code examples are going to use the following encoded secret:
`JEQDYMZAN5YGK3RAONXXK4TDMU`.

### Base

```rust
use otp_std::{Base, Secret};

fn main() {
    let secret = Secret::decode("JEQDYMZAN5YGK3RAONXXK4TDMU").unwrap();

    let base = Base::builder().secret(secret).build();

    let input = 0;

    let output = base.generate(input);

    assert!(base.verify(input, output));
}
```

### HOTP

```rust
use otp_std::{Base, Hotp, Secret};

fn main() {
    let secret = Secret::decode("JEQDYMZAN5YGK3RAONXXK4TDMU").unwrap();

    let counter = Counter::new(0);

    let base = Base::builder().secret(secret).build();
    let mut hotp = Hotp::builder().base(base).counter(counter).build();

    let code = hotp.generate();

    hotp.increment();  // increment the counter, as the code has been used

    let other = hotp.generate();

    assert_ne!(code, other);  // the codes have to be different because of the increment
}
```

### TOTP

```rust
use std::{thread::sleep, time::Duration};

use otp_std::{Base, Secret, Totp};

fn main() {
    let secret = Secret::decode("JEQDYMZAN5YGK3RAONXXK4TDMU").unwrap();

    let base = Base::builder().secret(secret).build();
    let totp = Totp::builder().base(base).build();

    let duration = Duration::from_secs(totp.period.get());

    let code = totp.generate();

    sleep(duration);

    let other = totp.generate();

    assert_ne!(code, other);
}
```

## Features

### `generate-secret`

The `generate-secret` feature enables secret generation:

```rust
use otp_std::{Length, Secret};

fn main() {
    let secret = Secret::generate(Length::default());

    println!("{secret}");
}
```

### `unsafe-length`

By default, `otp-std` does not allow secret length below `16` bytes.

Some services, however, generate secrets with length below the aforementioned limit.
To counter this, one can enable the `unsafe-length` feature:

```rust
use otp_std::{Length, Secret};

fn main() {
    let length = Length::new(10).unwrap();

    let secret = Secret::generate(length);

    println!("{secret}");
}
```

Note that unwrapping here is absolutely fine, as the `new` function returns `Result<Self, !>`
(i.e. it never returns an error). Conversely, this code would panic without `unsafe-length` because
`10 < 16`.

### `auth`

The `auth` feature implements building and parsing OTP URLs:

```rust
use otp_std::{Auth, Base, Label, Part, Secret, Totp};

fn main() {
    let secret = Secret::decode("JEQDYMZAN5YGK3RAONXXK4TDMU").unwrap();

    let base = Base::builder().secret(secret).build();
    let totp = Totp::builder().base(base).build();

    let issuer = Part::borrowed("MelodyKit").unwrap();
    let user = Part::borrowed("nekitdev").unwrap();

    let label = Label::builder().issuer(issuer).user(user).build();

    let auth = Auth::totp(totp, label);

    let url = auth.build_url();

    println!("{url}");

    let parsed = Auth::parse_url(url).unwrap();

    assert_eq!(auth, parsed);
}
```

### `sha2`

The default algorithm used by OTP is `SHA1`. In order to use `SHA256` or `SHA512`, one can enable
the `sha2` feature:

```rust
use otp_std::{Algorithm, Base, Secret, Totp};

fn main() {
    let secret = Secret::decode("JEQDYMZAN5YGK3RAONXXK4TDMU").unwrap();

    let base = Base::builder()
        .secret(secret)
        .algorithm(Algorithm::Sha256)
        .build();

    let totp = Totp::builder().base(base).build();

    let code = totp.generate();

    println!("{code}");
}
```

### `serde`

The `serde` feature, when enabled, implements `Serialize` and `Deserialize` for types provided
by `otp-std`:

```rust
use otp_std::{Base, Secret, Totp};
use serde_json::{json, to_value};

fn main() {
    let string = "JEQDYMZAN5YGK3RAONXXK4TDMU";

    let data = json!({
        "secret": string,
        // all of the following fields are optional
        "algorithm": "SHA1",
        "digits": 6,
        "skew": 1,
        "period": 30,
    });

    let secret = Secret::decode(string).unwrap();

    let base = Base::builder().secret(secret).build();
    let totp = Totp::builder().base(base).build();

    let value = to_value(&totp).unwrap();

    assert_eq!(value, data);
}
```

## Documentation

You can find the documentation [here][Documentation].

## Support

If you need support with the library, you can send an [email][Email].

## Changelog

You can find the changelog [here][Changelog].

## Security Policy

You can find the Security Policy of `otp-std` [here][Security].

## Contributing

If you are interested in contributing to `otp-std`, make sure to take a look at the
[Contributing Guide][Contributing Guide], as well as the [Code of Conduct][Code of Conduct].

## License

`otp-std` is licensed under the MIT License terms. See [License][License] for details.

[Email]: mailto:support@nekit.dev

[Discord]: https://nekit.dev/chat

[Actions]: https://github.com/nekitdev/otp-std/actions

[Changelog]: https://github.com/nekitdev/otp-std/blob/main/CHANGELOG.md
[Code of Conduct]: https://github.com/nekitdev/otp-std/blob/main/CODE_OF_CONDUCT.md
[Contributing Guide]: https://github.com/nekitdev/otp-std/blob/main/CONTRIBUTING.md
[Security]: https://github.com/nekitdev/otp-std/blob/main/SECURITY.md

[License]: https://github.com/nekitdev/otp-std/blob/main/LICENSE

[Crate]: https://crates.io/crates/otp-std
[Documentation]: https://docs.rs/otp-std

[License Badge]: https://img.shields.io/crates/l/otp-std
[Version Badge]: https://img.shields.io/crates/v/otp-std
[Downloads Badge]: https://img.shields.io/crates/dr/otp-std
[Test Badge]: https://github.com/nekitdev/otp-std/workflows/test/badge.svg
