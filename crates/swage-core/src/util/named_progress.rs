use indicatif::ProgressStyle;

/// Extension trait for creating named progress bars.
pub trait NamedProgress {
    /// Creates a progress bar style with a name label.
    ///
    /// # Arguments
    ///
    /// * `name` - Label to display with the progress bar
    fn named_bar(name: &str) -> Self;
}

impl NamedProgress for ProgressStyle {
    fn named_bar(name: &str) -> Self {
        let mut fmt = name.to_string();
        for _ in 0..(32 - name.len() as i64 - 1) {
            fmt += " ";
        }
        fmt +=
            "{wide_bar:40.cyan/blue} {pos:>3}/{len:<3} [{elapsed_precise} ({eta} remaining)] {msg}";
        ProgressStyle::default_bar()
            .template(&fmt)
            .unwrap_or(ProgressStyle::default_bar())
    }
}
