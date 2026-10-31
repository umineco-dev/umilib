use alloc::string::String;
use alloc::vec::Vec;

use super::MailError;

/// A cursor over the text of a structured header field, reading the
/// lexical tokens of RFC 5322 §3.2 and their obsolete forms (§4.1, §4.4):
/// folding white space, comments, atoms, quoted strings, domain literals.
/// With `utf8`, characters of UTF-8 are taken where RFC 6532 §3.2 takes
/// them (atext, qtext, ctext, dtext).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailReader<'a> {
    pub text: &'a [u8],
    pub position: usize,
    pub utf8: bool,
}

impl<'a> MailReader<'a> {
    /// The deepest nesting of comments read. A constant, not of `MailConfig`: comments are read
    /// with a counter, so their depth costs nothing, and what a field costs is bounded by
    /// `MailConfig::maximum_field_length`.
    pub const MAXIMUM_COMMENT_DEPTH: usize = 64;

    pub fn new(text: &'a [u8], utf8: bool) -> MailReader<'a> {
        MailReader { text, position: 0, utf8 }
    }

    pub fn is_end(&self) -> bool {
        self.position >= self.text.len()
    }

    pub fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    pub fn error(&self, reason: &'static str) -> MailError {
        MailError::Syntax { position: self.position, reason }
    }

    /// Takes `byte` if it is next.
    pub fn eat(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.position += 1;
        }
        next
    }

    pub fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), MailError> {
        match self.eat(byte) {
            true => Ok(()),
            false => Err(self.error(reason)),
        }
    }

    /// Whether `byte` is atext (RFC 5322 §3.2.3), a byte of UTF-8 too with `utf8`.
    pub fn is_atext(byte: u8, utf8: bool) -> bool {
        byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte) || (utf8 && byte >= 0x80)
    }

    /// Skips folding white space: spaces, tabs and line breaks (RFC 5322
    /// §3.2.2, §4.2; a header field read is already unfolded or folded at
    /// a line break followed by white space).
    pub fn skip_fws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    /// Skips CFWS: white space and comments, nested (RFC 5322 §3.2.2).
    pub fn skip_cfws(&mut self) -> Result<(), MailError> {
        loop {
            self.skip_fws();
            if self.peek() != Some(b'(') {
                return Ok(());
            }
            self.comment()?;
        }
    }

    /// Reads a comment, its nested comments and quoted pairs (RFC 5322 §3.2.2).
    pub fn comment(&mut self) -> Result<(), MailError> {
        let start = self.position;
        let mut depth = 0usize;
        while let Some(byte) = self.peek() {
            self.position += 1;
            match byte {
                b'(' => {
                    depth += 1;
                    if depth > MailReader::MAXIMUM_COMMENT_DEPTH {
                        return Err(self.error("comments nested too deep"));
                    }
                }
                b')' if depth == 0 => return Err(self.error("a comment closed that was not open")),
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                b'\\' if self.peek().is_some() => self.position += 1,
                byte if byte >= 0x80 && !self.utf8 => return Err(self.error("a byte of no character in a comment")),
                _ => {}
            }
        }
        Err(MailError::Syntax { position: start, reason: "a comment not closed" })
    }

    /// An atom, between CFWS (RFC 5322 §3.2.3).
    pub fn atom(&mut self) -> Result<&'a [u8], MailError> {
        self.skip_cfws()?;
        let start = self.position;
        while self.peek().is_some_and(|byte| MailReader::is_atext(byte, self.utf8)) {
            self.position += 1;
        }
        if self.position == start {
            return Err(self.error("not an atom"));
        }
        let atom = &self.text[start..self.position];
        self.skip_cfws()?;
        Ok(atom)
    }

    /// Whether `byte` is a character of a MIME token: US-ASCII but space,
    /// controls and tspecials (RFC 2045 §5.1).
    pub fn is_token(byte: u8) -> bool {
        (33..=126).contains(&byte) && !b"()<>@,;:\\\"/[]?=".contains(&byte)
    }

    /// A MIME token, between CFWS (RFC 2045 §5.1).
    pub fn token(&mut self) -> Result<&'a [u8], MailError> {
        self.skip_cfws()?;
        let start = self.position;
        while self.peek().is_some_and(MailReader::is_token) {
            self.position += 1;
        }
        if self.position == start {
            return Err(self.error("not a token"));
        }
        let token = &self.text[start..self.position];
        self.skip_cfws()?;
        Ok(token)
    }

    /// A dot-atom, between CFWS (RFC 5322 §3.2.3): atoms joined by single dots.
    pub fn dot_atom(&mut self) -> Result<&'a [u8], MailError> {
        self.skip_cfws()?;
        let start = self.position;
        loop {
            let begin = self.position;
            while self.peek().is_some_and(|byte| MailReader::is_atext(byte, self.utf8)) {
                self.position += 1;
            }
            if self.position == begin {
                return Err(self.error("not a dot-atom"));
            }
            if !(self.peek() == Some(b'.') && self.text.get(self.position + 1).is_some_and(|byte| *byte != b'.')) {
                break;
            }
            self.position += 1;
        }
        let atom = &self.text[start..self.position];
        self.skip_cfws()?;
        Ok(atom)
    }

    /// A quoted string, between CFWS, without its quotes and the backslashes
    /// of its quoted pairs; its folding kept as it is (RFC 5322 §3.2.4).
    pub fn quoted_string(&mut self) -> Result<Vec<u8>, MailError> {
        self.skip_cfws()?;
        let start = self.position;
        self.expect(b'"', "not a quoted string")?;
        let mut content = Vec::new();
        loop {
            match self.peek() {
                None => return Err(MailError::Syntax { position: start, reason: "a quoted string not closed" }),
                Some(b'"') => {
                    self.position += 1;
                    break;
                }
                Some(b'\\') => {
                    let quoted = self.text.get(self.position + 1).copied();
                    let quoted =
                        quoted.ok_or(MailError::Syntax { position: start, reason: "a quoted pair cut short" })?;
                    content.push(quoted);
                    self.position += 2;
                }
                // §3.2.2: folding is CRLF followed by white space, which unfolds to the white space.
                Some(b'\r' | b'\n') => self.position += 1,
                Some(byte) if byte >= 0x80 && !self.utf8 => {
                    return Err(self.error("a byte of no character in a quoted string"));
                }
                Some(byte) => {
                    content.push(byte);
                    self.position += 1;
                }
            }
        }
        self.skip_cfws()?;
        Ok(content)
    }

    /// A word: an atom or a quoted string (RFC 5322 §3.2.5).
    pub fn word(&mut self) -> Result<Vec<u8>, MailError> {
        self.skip_cfws()?;
        match self.peek() {
            Some(b'"') => self.quoted_string(),
            _ => self.atom().map(<[u8]>::to_vec),
        }
    }

    /// A phrase: words, and the dots of obs-phrase (§4.1), joined by single
    /// spaces as they were separated by white space.
    pub fn phrase(&mut self) -> Result<Vec<u8>, MailError> {
        let mut phrase = self.word()?;
        loop {
            self.skip_cfws()?;
            match self.peek() {
                Some(b'"') => {}
                Some(b'.') => {
                    self.position += 1;
                    phrase.push(b'.');
                    continue;
                }
                Some(byte) if MailReader::is_atext(byte, self.utf8) => {}
                _ => return Ok(phrase),
            }
            phrase.push(b' ');
            phrase.extend_from_slice(&self.word()?);
        }
    }

    /// A domain (RFC 5322 §3.4.1): a dot-atom, a domain literal with its
    /// brackets, or obs-domain (§4.4), atoms joined by dots with CFWS between.
    pub fn domain(&mut self) -> Result<String, MailError> {
        self.skip_cfws()?;
        if self.peek() == Some(b'[') {
            return self.domain_literal();
        }
        let mut domain = self.atom()?.to_vec();
        while self.eat(b'.') {
            domain.push(b'.');
            domain.extend_from_slice(self.atom()?);
        }
        self.text_of(domain)
    }

    /// A domain literal, with its brackets, its white space removed (RFC 5322 §3.4.1).
    pub fn domain_literal(&mut self) -> Result<String, MailError> {
        let start = self.position;
        self.expect(b'[', "not a domain literal")?;
        let mut literal = alloc::vec![b'['];
        loop {
            match self.peek() {
                None => return Err(MailError::Syntax { position: start, reason: "a domain literal not closed" }),
                Some(b']') => {
                    self.position += 1;
                    literal.push(b']');
                    break;
                }
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.position += 1,
                Some(b'[' | b'\\') => return Err(self.error("a character a domain literal does not take")),
                Some(byte) if byte >= 0x80 && !self.utf8 => {
                    return Err(self.error("a byte of no character in a domain literal"));
                }
                Some(byte) => {
                    literal.push(byte);
                    self.position += 1;
                }
            }
        }
        self.skip_cfws()?;
        self.text_of(literal)
    }

    /// A local part (RFC 5322 §3.4.1): a dot-atom or a quoted string, or
    /// obs-local-part (§4.4), words joined by dots. A quoted string is given
    /// unquoted.
    pub fn local_part(&mut self) -> Result<String, MailError> {
        let mut local = self.word()?;
        while self.eat(b'.') {
            local.push(b'.');
            local.extend_from_slice(&self.word()?);
        }
        self.text_of(local)
    }

    /// `bytes` as text: of UTF-8 (RFC 6532 §3.1).
    pub fn text_of(&self, bytes: Vec<u8>) -> Result<String, MailError> {
        String::from_utf8(bytes).map_err(|_| self.error("not UTF-8"))
    }
}
