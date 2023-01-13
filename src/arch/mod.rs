// Consider upstreaming aarch64 support to nix, see
// https://github.com/nix-rust/nix/issues/1678

#[cfg(target_arch = "aarch64")]
#[macro_use]
mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;

#[cfg(target_arch = "x86_64")]
#[macro_use]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;
