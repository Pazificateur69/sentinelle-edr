//! Capteur Windows de Sentinelle. Expose `run(host, handler)` sous Windows.
//! Sur les autres plateformes, le crate compile a vide (pour garder le workspace
//! buildable partout) et `run` renvoie une erreur explicite.

pub mod cmdline;

#[cfg(windows)]
mod etw;

#[cfg(windows)]
pub use etw::run;

#[cfg(not(windows))]
pub fn run<F>(_host: String, _handler: F) -> anyhow::Result<()>
where
    F: Fn(sentinelle_common::Event) + Send + Sync + 'static,
{
    anyhow::bail!("Le capteur ETW n'est disponible que sous Windows")
}
