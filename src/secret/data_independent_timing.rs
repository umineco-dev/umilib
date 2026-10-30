use core::marker::PhantomData;

/// Keeps the processor in its data-independent timing mode while it lives.
///
/// Without that mode some processors take time that depends on the values
/// they compute with, even in code without data-dependent branches or memory
/// accesses: Arm processors with FEAT_DIT (Apple silicon among them) until
/// `PSTATE.DIT` is set, and Intel processors until the operating system sets
/// DOITM. A guard sets `PSTATE.DIT` for the current thread when it is created
/// and restores the previous state when it is dropped, so guards nest; it
/// cannot move to another thread, because the mode belongs to the thread.
///
/// The mode is set only on targets compiled with the `dit` target feature
/// ([`DataIndependentTiming::AVAILABLE`]), which `aarch64-apple-*` targets
/// enable by default; on other targets a guard does nothing, and so it does
/// under Miri, which cannot run the instructions that read and write the mode. Constant-time
/// operations that take long take a guard themselves; code that combines many
/// short ones should hold one guard around the whole computation.
#[derive(Debug)]
pub struct DataIndependentTiming {
    previous: bool,
    thread: PhantomData<*const ()>,
}

impl DataIndependentTiming {
    /// Whether guards set the mode on this target.
    pub const AVAILABLE: bool = cfg!(all(target_arch = "aarch64", target_feature = "dit", not(miri)));

    /// Sets the mode until the guard is dropped.
    pub fn enable() -> DataIndependentTiming {
        let previous = DataIndependentTiming::is_enabled();
        if !previous {
            DataIndependentTiming::set(true);
        }
        DataIndependentTiming { previous, thread: PhantomData }
    }

    /// Whether the mode is set for the current thread (always false where it is not available).
    pub fn is_enabled() -> bool {
        #[cfg(all(target_arch = "aarch64", target_feature = "dit", not(miri)))]
        {
            let value: u64;
            // SAFETY: reading PSTATE.DIT has no side effects; FEAT_DIT is
            // guaranteed by the `dit` target feature.
            unsafe {
                core::arch::asm!("mrs {value}, DIT", value = out(reg) value, options(nomem, nostack, preserves_flags))
            };
            value & (1 << 24) != 0
        }
        #[cfg(not(all(target_arch = "aarch64", target_feature = "dit", not(miri))))]
        {
            false
        }
    }

    /// Sets or clears the mode for the current thread; does nothing where it is not available.
    pub fn set(enabled: bool) {
        #[cfg(all(target_arch = "aarch64", target_feature = "dit", not(miri)))]
        {
            // SAFETY: writing PSTATE.DIT only changes the timing of later
            // instructions; FEAT_DIT is guaranteed by the `dit` target feature.
            unsafe {
                if enabled {
                    core::arch::asm!("msr DIT, #1", options(nomem, nostack, preserves_flags));
                } else {
                    core::arch::asm!("msr DIT, #0", options(nomem, nostack, preserves_flags));
                }
            }
        }
        #[cfg(not(all(target_arch = "aarch64", target_feature = "dit", not(miri))))]
        let _ = enabled;
    }
}

impl Drop for DataIndependentTiming {
    fn drop(&mut self) {
        if !self.previous {
            DataIndependentTiming::set(false);
        }
    }
}
