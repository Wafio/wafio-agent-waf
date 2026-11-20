//! A dropped `CertificateInstall` leaves no key byte in the block it frees, whichever way it is
//! dropped. The allocator below reads every freed block of one size, so a drop path without the wipe
//! shows up as a block that still holds the key.

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use wafio_proto::v1::{CertificateInstall, ServerMessage, server_message::Kind};

/// The capacity of every key here, a size no other allocation of this test has.
const KEY_CAP: usize = 4099;

static FREED: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicUsize = AtomicUsize::new(0);

/// The system allocator that counts the freed blocks of `KEY_CAP` bytes and those among them with a
/// byte that is not zero.
struct Probe;

// SAFETY: every call goes to the system allocator unchanged; `dealloc` only reads the block first, and
// the block is still live then.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if l.size() == KEY_CAP {
            let block = unsafe { std::slice::from_raw_parts(p, l.size()) };
            FREED.fetch_add(1, SeqCst);
            if block.iter().any(|b| *b != 0) {
                DIRTY.fetch_add(1, SeqCst);
            }
        }
        unsafe { System.dealloc(p, l) };
    }
}

#[global_allocator]
static GLOBAL: Probe = Probe;

fn install() -> CertificateInstall {
    CertificateInstall {
        command_id: "cmd-1".into(),
        app_id: "app".into(),
        certificate_id: "cert".into(),
        chain_pem: b"chain".to_vec(),
        key_pem: vec![0xAA; KEY_CAP],
        leaf_sha256: "ab".repeat(32),
    }
}

/// Runs `f` and checks that it freed a key block and that every block it freed was zero.
fn frees_clean(what: &str, f: impl FnOnce()) {
    let (freed, dirty) = (FREED.load(SeqCst), DIRTY.load(SeqCst));
    f();
    assert!(FREED.load(SeqCst) > freed, "{what}: no key block was freed");
    assert_eq!(
        DIRTY.load(SeqCst),
        dirty,
        "{what}: a freed block held key bytes"
    );
}

// One test, as the counters are the process's: two tests in parallel would see each other's blocks.
#[test]
fn a_dropped_install_leaves_no_key_byte_in_the_block_it_frees() {
    // The probe sees a block that was not wiped, or the checks below prove nothing.
    let dirty = DIRTY.load(SeqCst);
    drop(std::hint::black_box(vec![0xAA_u8; KEY_CAP]));
    assert_eq!(
        DIRTY.load(SeqCst),
        dirty + 1,
        "the probe misses a dirty block"
    );

    frees_clean("plain drop", || drop(install()));

    // As the stream drain does with a message it never looks at.
    frees_clean("a message that holds an install", || {
        drop(ServerMessage {
            kind: Some(Kind::CertificateInstall(install())),
        });
    });

    frees_clean("a clone and its original", || {
        let m = install();
        drop(m.clone());
        drop(m);
    });

    frees_clean("a shortened key", || {
        let mut m = install();
        m.key_pem.truncate(10);
        drop(m);
    });

    frees_clean("a panic", || {
        let m = install();
        let r = catch_unwind(AssertUnwindSafe(move || {
            let _held = m;
            panic!("sink failed");
        }));
        assert!(r.is_err());
    });
}
