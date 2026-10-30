/// A digit of a big integer: the native word, so that products fit [`WideLimb`].
#[cfg(target_pointer_width = "64")]
pub type Limb = u64;
/// Twice a [`Limb`], holding a product of two limbs.
#[cfg(target_pointer_width = "64")]
pub type WideLimb = u128;
/// A digit of a big integer: the native word, so that products fit [`WideLimb`].
#[cfg(not(target_pointer_width = "64"))]
pub type Limb = u32;
/// Twice a [`Limb`], holding a product of two limbs.
#[cfg(not(target_pointer_width = "64"))]
pub type WideLimb = u64;
