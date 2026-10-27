//! Device-free ABI tests: the client's constants must match the C side
//! (`kmod/anchor.h`) exactly. The kernel side enforces the same numbers
//! at insmod (BUILD_BUG_ONs) and refuses unknown requests, so a drift
//! fails loudly on either side — never silently at runtime.

use swage_anchor::ioctl_request;
use swage_anchor::{AnchorStatus, BoundFrame, Ioctl, PageQuery, Transplant};

#[test]
fn request_numbers_are_the_kernel_encoding() {
    // _IOWR('A', nr, struct) per asm-generic ioctl.h:
    // (3 << 30) | (sizeof << 16) | (0x41 << 8) | nr.
    // Hand-computed from kmod/anchor.h:
    //   BIND        _IOWR('A', 0x01, 4*u64) = 0xC0204101
    //   TRANSPLANT  _IOWR('A', 0x02, 4*u64) = 0xC0204102
    //   QUERY       _IOWR('A', 0x03, 4*u64) = 0xC0204103
    //   RESTORE     _IOWR('A', 0x04, 3*u64) = 0xC0184104
    //   UNBIND      _IOWR('A', 0x05, 1*u64) = 0xC0084105
    //   STATUS      _IOWR('A', 0x06, 3*u64) = 0xC0184106
    assert_eq!(ioctl_request(Ioctl::Bind), 0xC020_4101);
    assert_eq!(ioctl_request(Ioctl::Transplant), 0xC020_4102);
    assert_eq!(ioctl_request(Ioctl::Query), 0xC020_4103);
    assert_eq!(ioctl_request(Ioctl::Restore), 0xC018_4104);
    assert_eq!(ioctl_request(Ioctl::Unbind), 0xC008_4105);
    assert_eq!(ioctl_request(Ioctl::Status), 0xC018_4106);
}

#[test]
fn every_request_is_distinct() {
    let all = [
        Ioctl::Bind,
        Ioctl::Transplant,
        Ioctl::Query,
        Ioctl::Restore,
        Ioctl::Unbind,
        Ioctl::Status,
    ];
    let mut reqs: Vec<u32> = all.iter().map(|op| op.request()).collect();
    reqs.sort_unstable();
    reqs.dedup();
    assert_eq!(reqs.len(), all.len(), "colliding request numbers");
}

#[test]
fn evidence_records_are_plain_data() {
    // The records serialize into campaign evidence; keep them Copy and
    // serde-plain (no handles leaked into the evidence: Transplant
    // carries PFNs only, BoundFrame the handle it owns).
    let frame = BoundFrame { handle: 7, pfn: 0x1234 };
    let t = Transplant {
        pid: 42,
        va: 0x2696_6000,
        frame_pfn: frame.pfn(),
        old_pfn: 0x99,
    };
    assert_eq!(t.frame_pfn, frame.pfn());
    let q = PageQuery { pfn: 0x1234, present: true };
    assert!(q.present);
    let s = AnchorStatus {
        bound_frames: 1,
        transplants: 1,
        kernel_version_code: 0x06080c,
    };
    assert_eq!(s.kernel_version_code, 6 << 16 | 8 << 8 | 12);
    let json = serde_json::to_value(&t).unwrap();
    assert_eq!(json.get("frame_pfn").and_then(|v| v.as_u64()), Some(0x1234));
}
