//! A system without a native layer (other than Linux, Android, Darwin and Windows).

use umilib::platform::native::System;

#[test]
fn the_system_is_named_other_and_unsupported() {
    const { assert!(!System::SUPPORTED) };
    assert_eq!(System::NAME, "other");
}
