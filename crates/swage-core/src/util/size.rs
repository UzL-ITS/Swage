/// Memory size representation supporting common units.
///
/// This enum provides a convenient way to specify memory sizes in bytes, kilobytes,
/// megabytes, or gigabytes. All units use binary (base-2) multipliers (1 KB = 1024 bytes).
///
/// # Examples
///
/// ```
/// use swage_core::util::Size;
///
/// let size = Size::MB(4);
/// assert_eq!(size.bytes(), 4 * 1024 * 1024);
///
/// let small = Size::KB(8);
/// assert_eq!(small.bytes(), 8192);
///
/// let large = Size::GB(2);
/// assert_eq!(large.bytes(), 2 * (1 << 30));
/// ```
#[derive(Clone, Copy, Debug)]
pub enum Size {
    /// Size in bytes
    B(usize),
    /// Size in kilobytes (1 KB = 1024 bytes)
    KB(usize),
    /// Size in megabytes (1 MB = 1024 KB)
    MB(usize),
    /// Size in gigabytes (1 GB = 1024 MB)
    GB(usize),
}

impl Size {
    /// Converts this size to bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use swage_core::util::Size;
    ///
    /// assert_eq!(Size::B(100).bytes(), 100);
    /// assert_eq!(Size::KB(1).bytes(), 1024);
    /// assert_eq!(Size::MB(1).bytes(), 1048576);
    /// assert_eq!(Size::GB(1).bytes(), 1073741824);
    /// ```
    pub const fn bytes(&self) -> usize {
        match self {
            Size::B(bytes) => *bytes,
            Size::KB(kb) => *kb * (1 << 10),
            Size::MB(mb) => *mb * (1 << 20),
            Size::GB(gb) => *gb * (1 << 30),
        }
    }
}

impl std::fmt::Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Size::B(bytes) => write!(f, "{} B", bytes),
            Size::KB(kb) => write!(f, "{} KB", kb),
            Size::MB(mb) => write!(f, "{} MB", mb),
            Size::GB(gb) => write!(f, "{} GB", gb),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::util::Size;

    #[test]
    fn size_conversions() {
        let bytes = Size::B(12);
        assert_eq!(bytes.bytes(), 12);
        let mb = Size::MB(12);
        assert_eq!(mb.bytes(), 12 * (1 << 20));
        let gb = Size::GB(12);
        assert_eq!(gb.bytes(), 12 * (1 << 30));
    }
}
