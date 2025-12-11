# Email Validator

An open-source library that provides a simple way to validate the structure of an email based on [RFC 3696](https://datatracker.ietf.org/doc/html/rfc3696#autoid-3). This project does not
ensure the email is actually valid—just that it *could* be valid. This is useful for instances where you want to validate user email input to ensure it correct.

## Usage

```rust
use email_validator::validate_email;

fn main() {
    let is_valid = validate_email("test@example.co");
    assert_eq!(is_valid, true);
    
    let is_valid = validate_email("test@example");
    assert_eq!(is_valid, false);
}
```

## Contributing

Note that this tool is not perfect and can allow invalid emails or may deny valid ones (very rarely). To see the types
of emails this tool allows, view the `tests` module. If you notice any errors, please create a pull request or issue
on GitHub.

If you would like to request a feature, please file an issue on GitHub before creating a pull request to ensure it will
be accepted.
