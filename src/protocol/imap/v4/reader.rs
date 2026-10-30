use alloc::string::String;
use alloc::vec::Vec;

use super::IMAPError;

/// A cursor over a whole command or response (its literals in it, its last
/// CRLF removed), reading the productions of RFC 9051 §9: atoms, numbers,
/// strings (quoted and literal), astrings, nstrings, lists, flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IMAPReader<'a> {
    pub data: &'a [u8],
    pub position: usize,
    /// How deep in lists the cursor is.
    pub depth: usize,
    pub maximum_depth: usize,
}

impl<'a> IMAPReader<'a> {
    pub fn new(data: &'a [u8], maximum_depth: usize) -> IMAPReader<'a> {
        IMAPReader { data, position: 0, depth: 0, maximum_depth }
    }

    /// Whether `byte` is an ATOM-CHAR: a CHAR but the atom-specials `(`, `)`, `{`, SP, CTL, `%`, `*`, `"`, `\` and `]`.
    pub fn is_atom_char(byte: u8) -> bool {
        (0x21..0x7f).contains(&byte) && !b"(){%*\"\\]".contains(&byte)
    }

    /// Whether `byte` is an ASTRING-CHAR: an ATOM-CHAR or `]`.
    pub fn is_astring_char(byte: u8) -> bool {
        IMAPReader::is_atom_char(byte) || byte == b']'
    }

    pub fn is_end(&self) -> bool {
        self.position >= self.data.len()
    }

    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.position).copied()
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.position.min(self.data.len())..]
    }

    pub fn error(&self, reason: &'static str) -> IMAPError {
        IMAPError::Syntax { position: self.position, reason }
    }

    pub fn eat(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.position += 1;
        }
        next
    }

    pub fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), IMAPError> {
        match self.eat(byte) {
            true => Ok(()),
            false => Err(self.error(reason)),
        }
    }

    /// Exactly one space (RFC 9051 §9 note 2).
    pub fn sp(&mut self) -> Result<(), IMAPError> {
        self.expect(b' ', "no space")
    }

    /// Fails unless the whole input has been read.
    pub fn end(&self) -> Result<(), IMAPError> {
        match self.is_end() {
            true => Ok(()),
            false => Err(self.error("more than the grammar takes")),
        }
    }

    /// Takes `keyword` in any case if it is next and not followed by an atom
    /// character (so that `UID` is not read from `UIDNEXT`).
    pub fn eat_keyword(&mut self, keyword: &str) -> bool {
        let end = self.position + keyword.len();
        let matches =
            self.data.get(self.position..end).is_some_and(|text| text.eq_ignore_ascii_case(keyword.as_bytes()));
        let whole = !self.data.get(end).is_some_and(|byte| IMAPReader::is_atom_char(*byte));
        if matches && whole {
            self.position = end;
        }
        matches && whole
    }

    /// Takes the characters of `text` in any case if they are next, whatever follows.
    pub fn eat_prefix(&mut self, text: &str) -> bool {
        let end = self.position + text.len();
        let matches = self.data.get(self.position..end).is_some_and(|next| next.eq_ignore_ascii_case(text.as_bytes()));
        if matches {
            self.position = end;
        }
        matches
    }

    /// The characters while `accept` takes them; fails if there are none.
    pub fn take_while(&mut self, accept: impl Fn(u8) -> bool, reason: &'static str) -> Result<&'a [u8], IMAPError> {
        let start = self.position;
        while self.peek().is_some_and(&accept) {
            self.position += 1;
        }
        match self.position > start {
            true => Ok(&self.data[start..self.position]),
            false => Err(self.error(reason)),
        }
    }

    /// An atom (RFC 9051 §4.1).
    pub fn atom(&mut self) -> Result<&'a [u8], IMAPError> {
        self.take_while(IMAPReader::is_atom_char, "not an atom")
    }

    /// An atom in upper case, as keywords compare without case.
    pub fn keyword(&mut self) -> Result<String, IMAPError> {
        let atom = self.atom()?;
        Ok(String::from_utf8_lossy(atom).to_ascii_uppercase())
    }

    /// A number of 32 bits (RFC 9051 §9 `number`).
    pub fn number(&mut self) -> Result<u32, IMAPError> {
        let value = self.number64()?;
        u32::try_from(value).map_err(|_| self.error("a number of more than 32 bits"))
    }

    /// A number of 1 or more (`nz-number`).
    pub fn nz_number(&mut self) -> Result<u32, IMAPError> {
        match self.number()? {
            0 => Err(self.error("zero where a non-zero number is")),
            value => Ok(value),
        }
    }

    /// A number of 63 bits (`number64`).
    pub fn number64(&mut self) -> Result<u64, IMAPError> {
        let digits = self.take_while(|byte| byte.is_ascii_digit(), "not a number")?;
        let value = core::str::from_utf8(digits).ok().and_then(|digits| digits.parse::<u64>().ok());
        value.filter(|value| *value <= i64::MAX as u64).ok_or(self.error("a number of more than 63 bits"))
    }

    /// A quoted string, its quoting removed (`quoted`): QUOTED-CHAR, of UTF-8 too (RFC 9051 §4.3).
    pub fn quoted(&mut self) -> Result<Vec<u8>, IMAPError> {
        self.expect(b'"', "not a quoted string")?;
        let mut text = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("a quoted string not closed")),
                Some(b'"') => {
                    self.position += 1;
                    break;
                }
                Some(b'\\') => match self.data.get(self.position + 1) {
                    Some(byte @ (b'"' | b'\\')) => {
                        text.push(*byte);
                        self.position += 2;
                    }
                    _ => return Err(self.error("a backslash before neither a quote nor a backslash")),
                },
                Some(b'\r' | b'\n' | 0) => return Err(self.error("a CR, LF or NUL in a quoted string")),
                Some(byte) => {
                    text.push(byte);
                    self.position += 1;
                }
            }
        }
        if core::str::from_utf8(&text).is_err() {
            return Err(self.error("a quoted string not of UTF-8"));
        }
        Ok(text)
    }

    /// A literal (`literal`, `{n}` or `{n+}` and CRLF and n octets), or,
    /// where `eight_bit`, a `literal8` (`~{n}`, RFC 3516).
    pub fn literal(&mut self, eight_bit: bool) -> Result<Vec<u8>, IMAPError> {
        let binary = eight_bit && self.eat(b'~');
        self.expect(b'{', "not a literal")?;
        let length = self.number64()?;
        self.eat(b'+');
        self.expect(b'}', "a literal not closed")?;
        if !self.rest().starts_with(b"\r\n") {
            return Err(self.error("no CRLF after the length of a literal"));
        }
        self.position += 2;
        let length = usize::try_from(length).map_err(|_| self.error("a literal longer than the input"))?;
        let data = self
            .data
            .get(self.position..self.position.saturating_add(length))
            .ok_or(self.error("a literal longer than the input"))?;
        if !binary && data.contains(&0) {
            return Err(self.error("a NUL in a literal"));
        }
        self.position += length;
        Ok(data.to_vec())
    }

    /// A string: quoted or literal.
    pub fn string(&mut self) -> Result<Vec<u8>, IMAPError> {
        match self.peek() {
            Some(b'"') => self.quoted(),
            Some(b'{') => self.literal(false),
            _ => Err(self.error("not a string")),
        }
    }

    /// An astring: ASTRING-CHARs, or a string.
    pub fn astring(&mut self) -> Result<Vec<u8>, IMAPError> {
        match self.peek() {
            Some(b'"' | b'{') => self.string(),
            _ => Ok(self.take_while(IMAPReader::is_astring_char, "not an astring")?.to_vec()),
        }
    }

    /// An nstring: a string, or NIL.
    pub fn nstring(&mut self) -> Result<Option<Vec<u8>>, IMAPError> {
        if self.eat_keyword("NIL") {
            return Ok(None);
        }
        self.string().map(Some)
    }

    /// An astring as text of UTF-8.
    pub fn astring_text(&mut self) -> Result<String, IMAPError> {
        let position = self.position;
        String::from_utf8(self.astring()?).map_err(|_| IMAPError::Syntax { position, reason: "not UTF-8" })
    }

    /// A flag: `\` and an atom, or an atom (a keyword); `\*` where `wildcard` (flag-perm).
    pub fn flag(&mut self, wildcard: bool) -> Result<String, IMAPError> {
        let start = self.position;
        if self.eat(b'\\') {
            if wildcard && self.eat(b'*') {
                return Ok(String::from("\\*"));
            }
            self.atom()?;
        } else {
            self.atom()?;
        }
        Ok(String::from_utf8_lossy(&self.data[start..self.position]).into_owned())
    }

    /// A parenthesized list (RFC 9051 §4.4) of what `item` reads, separated by single spaces.
    pub fn list<T>(
        &mut self,
        mut item: impl FnMut(&mut IMAPReader<'a>) -> Result<T, IMAPError>,
    ) -> Result<Vec<T>, IMAPError> {
        self.expect(b'(', "not a list")?;
        self.depth += 1;
        if self.depth > self.maximum_depth {
            return Err(self.error("lists nested too deep"));
        }
        let mut items = Vec::new();
        if !self.eat(b')') {
            loop {
                items.push(item(self)?);
                if self.eat(b')') {
                    break;
                }
                self.sp()?;
            }
        }
        self.depth -= 1;
        Ok(items)
    }

    /// The rest of the line as text (`text`): no CR or LF; UTF-8 where it is.
    pub fn text(&mut self) -> Result<String, IMAPError> {
        let rest = self.rest();
        if rest.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(self.error("a CR, LF or NUL in text"));
        }
        self.position = self.data.len();
        Ok(String::from_utf8_lossy(rest).into_owned())
    }

    /// The text of a `base64` production up to the end, strictly (RFC 9051 §9: base64-char,
    /// the padding only at the end).
    pub fn base64(&mut self) -> Result<Vec<u8>, IMAPError> {
        use crate::codec::base::Encoding;
        let rest = self.rest();
        let data = crate::codec::base::base64::Base64::STANDARD.decode(rest).map_err(|_| self.error("not base64"))?;
        self.position = self.data.len();
        Ok(data)
    }
}
