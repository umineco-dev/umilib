use umilib::hash::Digest;
use umilib::hash::sm3::SM3;

use crate::Vectors;

/// The hexadecimal words of `lines`, joined, skipping page headers and footers.
fn hex_block(lines: &[&str]) -> Vec<u8> {
    let words: String = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit() || c == ' '))
        .collect::<Vec<_>>()
        .join("");
    Vectors::hex(&words)
}

#[test]
fn sm3_follows_the_examples_of_draft_sca_cfrg_sm3() {
    let text = Vectors::read("hash/sm3/draft-sca-cfrg-sm3-02.txt");
    let lines: Vec<&str> = text.lines().collect();
    // Appendix A: the two examples of GB/T 32905-2016.
    let position = |prefix: &str| lines.iter().position(|line| line.starts_with(prefix)).unwrap();
    let first = hex_block(&lines[position("A.1.5.  Hash Value") + 1..position("A.2.  Example 2")]);
    assert_eq!(SM3::digest(b"abc").to_vec(), first);
    let second = hex_block(&lines[position("A.2.3.  Hash Value") + 1..position("Appendix B.  Example Results")]);
    assert_eq!(SM3::digest(&b"abcd".repeat(16)).to_vec(), second);
    // Appendix B: SM3 of the values of the SM2 examples.
    let sections: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("B.") && line.contains("GB/T 32918"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(sections.len(), 18);
    for (number, &start) in sections.iter().enumerate() {
        let end = sections.get(number + 1).copied().unwrap_or(position("Appendix C."));
        let section = &lines[start..end];
        let input = section.iter().position(|line| line.trim() == "Input:").unwrap();
        let output = section.iter().position(|line| line.trim() == "Output:").unwrap();
        let message = hex_block(&section[input + 1..output]);
        let expected = hex_block(&section[output + 1..]);
        assert_eq!(SM3::digest(&message).to_vec(), expected, "{}", lines[start]);
    }
}
