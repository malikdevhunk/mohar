//! Byte spans and the source file they index.

/// A half-open byte range into a [`SourceFile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub const DUMMY: Span = Span { start: 0, end: 0 };

    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    pub fn merge(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// One compilation input.
#[derive(Clone, Debug)]
pub struct SourceFile {
    pub name: String,
    pub source: String,
    line_starts: Vec<u32>,
}

impl SourceFile {
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        let source = source.into();
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        Self {
            name: name.into(),
            source,
            line_starts,
        }
    }

    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        let offset = offset.min(self.source.len() as u32);
        let idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let line_start = self.line_starts[idx];
        let col = byte_to_char_col(&self.source, line_start, offset);
        ((idx as u32) + 1, col)
    }

    pub fn line_text(&self, line: u32) -> &str {
        let idx = line.saturating_sub(1) as usize;
        if idx >= self.line_starts.len() {
            return "";
        }
        let start = self.line_starts[idx] as usize;
        let end = if idx + 1 < self.line_starts.len() {
            self.line_starts[idx + 1] as usize
        } else {
            self.source.len()
        };
        let raw = &self.source[start..end];
        raw.trim_end_matches(['\n', '\r'])
    }

    pub fn snippet(&self, span: Span) -> &str {
        let start = (span.start as usize).min(self.source.len());
        let end = (span.end as usize).min(self.source.len()).max(start);
        &self.source[start..end]
    }
}

fn byte_to_char_col(source: &str, line_start: u32, offset: u32) -> u32 {
    let start = line_start as usize;
    let end = (offset as usize).min(source.len());
    if start > end || start > source.len() {
        return 1;
    }
    let slice = &source[start..end];
    // Columns are Unicode scalar values, 1-based. Tabs count as one column;
    // the caret line uses the same measure so the two stay aligned.
    (slice.chars().count() as u32) + 1
}
