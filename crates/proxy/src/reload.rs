//! Reloads the policy file while the proxy runs, without a restart.
//!
//! The file is read every few seconds and reloaded when its content changed.
//! Polling works the same on every OS and with Kubernetes ConfigMaps, which
//! are swapped through a symlink. A file that does not parse or needs a model
//! that is not loaded is logged and ignored: the policy in force stays.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{metrics, Policy, Proxy};

/// What a check of the policy file did.
#[derive(Debug, PartialEq)]
pub enum Reload {
    Unchanged,
    Reloaded,
    /// The file changed but was rejected; the message says why.
    Rejected(String),
}

/// Watches one policy file for a proxy.
#[derive(Debug)]
pub struct Watcher {
    path: PathBuf,
    /// Hash of the content last seen, loaded or not.
    seen: Option<u64>,
}

impl Watcher {
    /// A watcher for `path`, which the proxy has already loaded.
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            seen: std::fs::read(path).ok().map(|c| hash(&c)),
        }
    }

    /// Reloads the policy into `proxy` if the file changed since the last check.
    pub fn check(&mut self, proxy: &Proxy) -> Reload {
        let Ok(content) = std::fs::read(&self.path) else {
            // Missing for a moment while an editor or ConfigMap swaps it.
            return Reload::Unchanged;
        };
        let h = hash(&content);
        if self.seen == Some(h) {
            return Reload::Unchanged;
        }
        self.seen = Some(h);
        let loaded = std::str::from_utf8(&content)
            .map_err(anyhow::Error::from)
            .and_then(Policy::from_yaml)
            .and_then(|policy| proxy.reload(policy));
        let result = if loaded.is_ok() { "ok" } else { "error" };
        metrics::count("promptwall_policy_reloads_total", &[("result", result)], 1);
        match loaded {
            Ok(()) => Reload::Reloaded,
            Err(err) => Reload::Rejected(format!("{err:#}")),
        }
    }
}

/// Checks the policy file every `interval`, forever, and logs what changed.
pub async fn watch(proxy: Proxy, path: PathBuf, interval: Duration) {
    let mut watcher = Watcher::new(&path);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match watcher.check(&proxy) {
            Reload::Unchanged => {}
            Reload::Reloaded => {
                let routes: Vec<String> = proxy
                    .policy()
                    .routes
                    .iter()
                    .map(|r| r.name.clone())
                    .collect();
                tracing::info!(?routes, policy = %path.display(), "policy reloaded");
            }
            Reload::Rejected(why) => tracing::error!(
                policy = %path.display(),
                error = %why,
                "policy not reloaded, the previous one stays in force"
            ),
        }
    }
}

fn hash(content: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}
