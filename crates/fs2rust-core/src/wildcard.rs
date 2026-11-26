/// Pure-Rust wildcard matcher supporting `*` (0+ chars), `?` (1 char),
/// `;` or `,` separated multi-patterns, and configurable case sensitivity.
#[derive(Debug, Clone)]
pub struct WildcardMatcher {
    patterns: Vec<Vec<char>>,
    case_sensitive: bool,
}

impl WildcardMatcher {
    /// Compile one or more wildcard patterns separated by `;` or `,`.
    pub fn new(spec: &str, case_sensitive: bool) -> Self {
        let patterns = spec
            .split([';', ','])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| {
                if case_sensitive {
                    p.chars().collect()
                } else {
                    p.chars().map(|c| c.to_ascii_lowercase()).collect()
                }
            })
            .collect();
        Self {
            patterns,
            case_sensitive,
        }
    }

    /// Compile a slice of individual pattern strings.
    pub fn from_patterns(patterns: &[String], case_sensitive: bool) -> Self {
        let mut compiled = Vec::new();
        for pat in patterns {
            for part in pat.split([';', ',']).map(str::trim).filter(|s| !s.is_empty()) {
                let chars = if case_sensitive {
                    part.chars().collect()
                } else {
                    part.chars().map(|c| c.to_ascii_lowercase()).collect()
                };
                compiled.push(chars);
            }
        }
        Self {
            patterns: compiled,
            case_sensitive,
        }
    }

    /// Returns `true` if no patterns were supplied.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns `true` if `candidate` matches at least one compiled pattern.
    pub fn is_match(&self, candidate: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let input: Vec<char> = if self.case_sensitive {
            candidate.chars().collect()
        } else {
            candidate.chars().map(|c| c.to_ascii_lowercase()).collect()
        };
        self.patterns.iter().any(|pat| match_glob(pat, &input))
    }
}

fn match_glob(pattern: &[char], text: &[char]) -> bool {
    let mut p_idx = 0usize;
    let mut t_idx = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == '?' || pattern[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == '*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(s_idx) = star_idx {
            p_idx = s_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < pattern.len() && pattern[p_idx] == '*' {
        p_idx += 1;
    }

    p_idx == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_star_and_question_multi_patterns() {
        let m = WildcardMatcher::new("*.rs; *.toml, report_??.txt", false);
        assert!(m.is_match("MAIN.RS"));
        assert!(m.is_match("Cargo.toml"));
        assert!(m.is_match("report_01.txt"));
        assert!(!m.is_match("report_1.txt"));
        assert!(!m.is_match("notes.md"));
    }

    #[test]
    fn wildcard_case_sensitivity_is_respected() {
        let cs = WildcardMatcher::new("Foo*.TXT", true);
        assert!(cs.is_match("FooBar.TXT"));
        assert!(!cs.is_match("foobar.txt"));

        let ci = WildcardMatcher::new("Foo*.TXT", false);
        assert!(ci.is_match("foobar.txt"));
    }
}
