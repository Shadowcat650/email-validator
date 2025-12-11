#![cfg_attr(not(feature = "std"), no_std)]

/// Checks the syntax of an email to see if it is valid.
pub fn validate_email(email: &str) -> bool {
    match validate_local(email) {
        Some(domain_start) => validate_domain(&email[domain_start..]),
        None => false,
    }
}

/// Checks if a character can normally appear in local portion of the email.
///
/// Note: Does not include: '.'
fn is_valid_non_escaped(c: char) -> bool {
    match c {
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_'
        | '`' | '{' | '|' | '}' | '~' => true,
        _ => c.is_alphanumeric(),
    }
}

/// Checks if a character is valid within a quote.
///
/// If this is false, the character must be escaped.
fn is_valid_quoted(c: char) -> bool {
    match c {
        ' ' | '@' | ',' | '[' | ']' | '.' => true,
        _ => is_valid_non_escaped(c),
    }
}

/// Checks if an escaped character is valid within a quote.
fn is_valid_quoted_escape(c: char) -> bool {
    match c {
        '\\' | '\"' => true,
        _ => false,
    }
}

/// Checks if a non-quoted escaped character is valid.
fn is_valid_escape(c: char) -> bool {
    match c {
        ' ' | '@' | '\\' | '\"' | ',' | '[' | ']' => true,
        _ => false,
    }
}

/// The current state when validating the local portion.
#[derive(Eq, PartialEq, Debug)]
enum LocalState {
    /// No characters have been validated yet.
    Start,

    /// Nothing interesting has happened.
    Normal,

    /// The previous character was a period ('.').
    NormalPeriod,

    /// The previous character was a backslash ('\'), which escapes the next character.
    Escaped,

    /// Nothing interesting, except we are in a quote.
    QuotedNormal,

    /// We are in a quote where the previous character was a backslash ('\'), which escapes the next character.
    QuotedEscaped,

    /// A quote just ended, meaning the previous character was a double quote ('"').
    QuotedEnd,

    /// The local portion has ended, meaning an at sign ('@') was found.
    End,
}

impl LocalState {
    /// Returns the next state if the character is valid.
    fn transition(self, c: char) -> Option<Self> {
        match self {
            LocalState::Start => {
                // // Is the character normally valid in the local portion?
                // Periods are excluded by this function.
                if is_valid_non_escaped(c) {
                    return Some(LocalState::Normal);
                }

                // Is there an escaped character?
                if c == '\\' {
                    return Some(LocalState::Escaped);
                }

                // Did a quote begin?
                if c == '\"' {
                    return Some(LocalState::QuotedNormal);
                }

                // Nothing else is valid.
                None
            }
            LocalState::Normal => {
                // Is the character normally valid in the local portion?
                if is_valid_non_escaped(c) {
                    return Some(LocalState::Normal);
                }

                // Is the character a period?
                if c == '.' {
                    return Some(LocalState::NormalPeriod);
                }

                // Did the local portion end?
                if c == '@' {
                    return Some(LocalState::End);
                }

                // Is there an escaped character?
                if c == '\\' {
                    return Some(LocalState::Escaped);
                }

                // Nothing else is valid.
                None
            }
            LocalState::NormalPeriod => {
                // Is the character normally valid in the local portion?
                if is_valid_non_escaped(c) {
                    return Some(LocalState::Normal);
                }

                // Is there an escaped character?
                if c == '\\' {
                    return Some(LocalState::Escaped);
                }

                // At signs ('@') are not valid after a period.

                // Nothing else is valid.
                None
            }
            LocalState::Escaped => {
                // Is the escaped character valid?
                if is_valid_escape(c) {
                    return Some(LocalState::Normal);
                }

                // Nothing else can be accepted.
                None
            }
            LocalState::QuotedNormal => {
                // Is this character normally valid in a quote?
                if is_valid_quoted(c) {
                    return Some(LocalState::QuotedNormal);
                }

                // Did the quote end?
                if c == '\"' {
                    return Some(LocalState::QuotedEnd);
                }

                // Is something escaped?
                if c == '\\' {
                    return Some(LocalState::QuotedEscaped);
                }

                // Nothing else is valid.
                None
            }
            LocalState::QuotedEscaped => {
                // Is the escaped character valid?
                if is_valid_quoted_escape(c) {
                    return Some(LocalState::QuotedNormal);
                }

                // Nothing else can be accepted.
                None
            }
            LocalState::QuotedEnd => {
                // Did the local portion end?
                if c == '@' {
                    return Some(LocalState::End);
                }

                // Nothing else is allowed to appear after a quote ends.
                None
            }

            // Nothing (in the local portion) can appear after the local portion ends.
            LocalState::End => None,
        }
    }
}

/// Validates the local portion of an email.
fn validate_local(email: &str) -> Option<usize> {
    let mut state = LocalState::Start;
    for (i, c) in email.char_indices() {
        // Check if the local portion has ended.
        if state == LocalState::End {
            // Make sure the local portion is not too long.
            // Subtract one for the at sign ('@').
            if (i - 1) > 64 {
                return None;
            }
            return Some(i);
        }

        // Attempt to transition to the next state.
        match state.transition(c) {
            None => return None,
            Some(new_state) => state = new_state,
        }
    }

    // We never hit the end state, so the local portion is invalid.
    None
}

/// The current state when validating the domain portion.
#[derive(Eq, PartialEq, Debug)]
enum DomainState {
    /// No characters have been validated yet.
    Start,

    /// Nothing interesting has happened.
    Normal,

    /// A dash ('-') was the previous character.
    Dash,

    /// A period ('.') was the previous character.
    StartDotted,

    /// Nothing interesting has happened since the DNS dot was found.
    ///
    /// The domain is currently valid.
    NormalDotted,

    /// A dash ('-') was the previous character and the DNS dot was found.
    DashDotted,
}

impl DomainState {
    /// Returns the next state if the character is valid.
    fn transition(self, c: char) -> Option<Self> {
        match self {
            DomainState::Start => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::Normal);
                }

                // Nothing else is valid.
                None
            }
            DomainState::Normal => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::Normal);
                }

                // Is the character a dash ('-')?
                if c == '-' {
                    return Some(DomainState::Dash);
                }

                // Is the character a period ('.')?
                if c == '.' {
                    return Some(DomainState::StartDotted);
                }

                // Nothing else is valid.
                None
            }
            DomainState::Dash => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::Normal);
                }

                // Is the character a dash ('-')?
                if c == '-' {
                    return Some(DomainState::Dash);
                }

                // Nothing else is valid.
                None
            }
            DomainState::StartDotted => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::NormalDotted);
                }

                // Nothing else is valid.
                None
            }
            DomainState::NormalDotted => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::NormalDotted);
                }

                // Is the character a dash ('-')?
                if c == '-' {
                    return Some(DomainState::DashDotted);
                }

                // Is the character a period ('.')?
                if c == '.' {
                    return Some(DomainState::StartDotted);
                }

                // Nothing else is valid.
                None
            }
            DomainState::DashDotted => {
                // Is the character a letter or number?
                if c.is_ascii_alphanumeric() {
                    return Some(DomainState::NormalDotted);
                }

                // Is the character a dash ('-')?
                if c == '-' {
                    return Some(DomainState::DashDotted);
                }

                // Nothing else is valid.
                None
            }
        }
    }
}

/// Validates the domain portion of an email.
fn validate_domain(domain: &str) -> bool {
    // Make sure the domain is not too long.
    if domain.len() > 255 {
        return false;
    }

    let mut state = DomainState::Start;
    for c in domain.chars() {
        // Attempt to transition to the next state.
        match state.transition(c) {
            None => return false,
            Some(new_state) => state = new_state,
        }
    }

    // The domain has been parsed and the last portion is in a good state.
    state == DomainState::NormalDotted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This email should be valid.
    fn check(str: &str) {
        assert!(validate_email(&str));
    }

    /// This email should be invalid.
    fn x(str: &str) {
        assert!(!validate_email(&str));
    }

    #[test]
    fn normal_email() {
        check("normalemail@example.com");
    }

    #[test]
    fn normal_plus() {
        check("user+mailbox@example.com");
    }

    #[test]
    fn normal_slash_eq() {
        check("customer/department=shipping@example.com");
    }

    #[test]
    fn normal_dollar() {
        check("$A12345@example.com");
    }

    #[test]
    fn normal_exclamation_percent() {
        check("!def!xyz%abc@example.com");
    }

    #[test]
    fn normal_underscore() {
        check("_somename@example.com");
    }

    #[test]
    fn normal_apostrophe_acute_accent() {
        check("lol`'lol'@example.com");
    }

    #[test]
    fn normal_crazy_symbols() {
        check("!#$%&'*+-/=?^_`{|}~@example.com");
    }

    #[test]
    fn normal_dot() {
        check("a.name@example.com");
    }

    #[test]
    fn escaped_at() {
        check("Abc\\@def@example.com");
    }

    #[test]
    fn escaped_space() {
        check("Fred\\ Bloggs@example.com");
    }

    #[test]
    fn escaped_backslash() {
        check("Joe.\\\\Blow@example.com");
    }

    #[test]
    fn all_escaped() {
        check("\\\\\\ \\\"\\,\\[\\]@example.com");
    }

    #[test]
    fn quoted_at() {
        check("\"Abc@def\"@example.com");
    }

    #[test]
    fn quoted_space() {
        check("\"Fred Bloggs\"@example.com");
    }

    #[test]
    fn all_quoted() {
        check("\"this is..quoted [te,xt]\"@example.com");
    }

    #[test]
    fn all_escaped_quoted() {
        check("\"\\\\\\\"\"@example.com");
    }

    #[test]
    fn almost_too_long_local() {
        check("thisisnotaslonglocalportionofanemailaddressthatshouldberejected1@example.com");
    }

    #[test]
    fn subdomains() {
        check("example@sub.domain.com");
    }

    #[test]
    fn domain_single_dash() {
        check("example@domain-x.com");
    }

    #[test]
    fn domain_multi_dash() {
        check("example@domain--x.com");
    }

    #[test]
    fn almost_long_domain() {
        check(
            "example@thisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlyandwillnowrepeattisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlywowwhyoneartharethismanycharactersallowedmypooridecannotrenderinonescreenalmostdone1.com",
        );
    }

    #[test]
    fn almost_long_email() {
        check(
            "thisisnotaslonglocalportionofanemailaddressthatshouldberejected1@thisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlyandwillnowrepeattisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlywowwhyoneartharethismanycharactersallowedmypooridecannotrenderinonescreenalmostdone1.com",
        );
    }

    // Bad

    #[test]
    fn start_dot() {
        x(".example@example.com");
    }

    #[test]
    fn double_dot() {
        x("example..name@example.com");
    }

    #[test]
    fn end_dot() {
        x("example.@example.com");
    }

    #[test]
    fn empty_local() {
        x("@example.com");
    }

    #[test]
    fn no_domain() {
        x("myname");
    }

    #[test]
    fn unescaped_quote() {
        x("my\"name@example.com");
    }

    #[test]
    fn things_after_quote() {
        x("\"quoted\"abc@example.com");
    }

    #[test]
    fn too_long_local() {
        x("thisisasuperlonglocalportionofanemailaddressthatshouldberejected1@example.com");
    }

    #[test]
    fn domain_start_dot() {
        x("example@.domain.com");
    }

    #[test]
    fn domain_end_dot() {
        x("example@domain.com.");
    }

    #[test]
    fn domain_with_double_dot() {
        x("example@domain..com");
    }

    #[test]
    fn domain_start_dash() {
        x("example@-domain.com");
    }

    #[test]
    fn domain_end_dash() {
        x("example@domain-.com");
    }

    #[test]
    fn tld_end_dash() {
        x("example@domain.com-");
    }

    #[test]
    fn domain_without_tld() {
        x("example@domain");
    }

    #[test]
    fn domain_with_only_tld() {
        x("example@.com");
    }

    #[test]
    fn domain_with_space() {
        x("example@example .com");
    }

    #[test]
    fn long_domain() {
        x(
            "example@thisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlyandwillnowrepeatthisisalongdomainnamethatshouldberejectedifihaveimplementedthelogiccorrectlywowwhyoneartharethismanycharactersallowedmypooridecannotrenderinonescreenalmostdone1.com",
        );
    }
}
