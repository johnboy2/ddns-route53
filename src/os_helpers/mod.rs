// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

pub trait PlatformStringDecoder {
    fn decode(&self, data: &[u8]) -> anyhow::Result<String>;

    #[allow(dead_code)]
    fn description(&self) -> std::borrow::Cow<'_, str>;

    #[allow(dead_code)]
    fn name(&self) -> std::borrow::Cow<'_, str>;
}

#[cfg(unix)]
pub mod posix;

#[cfg(unix)]
pub use self::posix::*;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use self::windows::*;

#[cfg(all(not(unix), not(windows)))]
mod other;

#[cfg(all(not(unix), not(windows)))]
pub use self::other::*;
