//! Storage quota accounting for the whole data directory.
//!
//! Usage is kept in memory: it is computed once at startup by walking the data
//! directory, then updated by the write paths. Every write reserves the bytes it
//! is about to put on disk *before* writing them, under a single lock, so
//! concurrent uploads can never exceed the limit together.
//!
//! Operations whose exact size delta is awkward to compute (versioned writes and
//! deletes, bucket deletion, expired upload cleanup) mark the counter "dirty";
//! a background task then recounts the data directory (debounced). A periodic
//! recount also reconciles small files that are not tracked individually
//! (metadata sidecars, ACLs, encryption tags).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::error::S3Error;
use crate::storage::TMP_DIR;

/// Number of stripes for per-path locks (see `Quota::lock_path`).
const PATH_LOCK_STRIPES: usize = 64;

/// Minimum delay between two background recounts triggered by `mark_dirty`.
const RECOUNT_DEBOUNCE: Duration = Duration::from_millis(500);

#[derive(Default)]
struct State {
    /// Bytes on disk (last recount + committed writes - known deletions).
    used: u64,
    /// Bytes reserved by in-flight writes, not yet committed.
    reserved: u64,
    /// True while a recount walks the data directory.
    scanning: bool,
    /// Bytes committed while a recount was in progress (added back to the scan result).
    committed_during_scan: u64,
}

/// Snapshot of the quota state (figures exposed by `/_loch/usage`, the state by `/_loch/health`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaUsage {
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub limit_bytes: Option<u64>,
}

/// Storage quota for the data directory. A `None` limit means unlimited
/// (usage is still tracked and reported).
pub struct Quota {
    limit: Option<u64>,
    state: Mutex<State>,
    dirty: Notify,
    /// Serializes recounts (background worker and periodic task).
    recount_lock: tokio::sync::Mutex<()>,
    /// Striped locks serializing "stat old size, rename/remove, update counter"
    /// sequences on the same destination path.
    path_locks: Vec<tokio::sync::Mutex<()>>,
}

impl Quota {
    pub fn new(limit: Option<u64>) -> Self {
        Self {
            limit,
            state: Mutex::new(State::default()),
            dirty: Notify::new(),
            recount_lock: tokio::sync::Mutex::new(()),
            path_locks: (0..PATH_LOCK_STRIPES)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
        }
    }

    /// Unlimited quota (used by `Storage::new`).
    pub fn unlimited() -> Self {
        Self::new(None)
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Lock a destination path while its previous size is read, the file is
    /// replaced or removed, and the counter is updated. Without it, two concurrent
    /// overwrites of the same key would both release the same old size.
    /// Never hold two path locks at once (stripes may collide).
    pub async fn lock_path(&self, path: &Path) -> tokio::sync::MutexGuard<'_, ()> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        let index = (hasher.finish() as usize) % PATH_LOCK_STRIPES;
        self.path_locks[index].lock().await
    }

    /// Lock the state; a poisoned lock (panic while held) is still usable since
    /// every critical section leaves the counters consistent.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True when usage has reached the limit: no write of one byte or more can succeed.
    pub fn is_exceeded(&self) -> bool {
        let usage = self.usage();
        matches!(usage.limit_bytes, Some(limit) if usage.used_bytes >= limit)
    }

    pub fn usage(&self) -> QuotaUsage {
        let state = self.lock();
        QuotaUsage {
            used_bytes: state.used,
            reserved_bytes: state.reserved,
            limit_bytes: self.limit,
        }
    }

    /// Start a reservation for a write. `factor` is the number of on-disk copies
    /// each written byte will produce (2 when the bucket keeps versions).
    pub fn reservation(self: &Arc<Self>, factor: u64) -> Reservation {
        Reservation {
            quota: self.clone(),
            factor: factor.max(1),
            reserved: 0,
            committed: false,
        }
    }

    /// Try to reserve `n` more bytes. Fails with `QuotaExceeded` if the limit would be crossed.
    fn try_reserve(&self, n: u64) -> Result<(), S3Error> {
        let mut state = self.lock();
        if let Some(limit) = self.limit {
            let total = state.used.saturating_add(state.reserved).saturating_add(n);
            if total > limit {
                return Err(S3Error::QuotaExceeded);
            }
        }
        state.reserved += n;
        Ok(())
    }

    fn release_reservation(&self, n: u64) {
        let mut state = self.lock();
        state.reserved = state.reserved.saturating_sub(n);
    }

    fn commit_reservation(&self, reserved: u64, actual: u64) {
        let mut state = self.lock();
        state.reserved = state.reserved.saturating_sub(reserved);
        state.used = state.used.saturating_add(actual);
        if state.scanning {
            state.committed_during_scan = state.committed_during_scan.saturating_add(actual);
        }
    }

    /// Record bytes added to disk without a limit check (space-neutral operations
    /// such as assembling already-counted multipart parts).
    pub fn add(&self, n: u64) {
        self.commit_reservation(0, n);
    }

    /// Record bytes removed from disk.
    pub fn release(&self, n: u64) {
        let mut state = self.lock();
        state.used = state.used.saturating_sub(n);
    }

    /// Fail with `QuotaExceeded` if usage already exceeds the limit
    /// (a zero-byte reservation: same check as any write).
    pub fn check_not_exceeded(&self) -> Result<(), S3Error> {
        self.try_reserve(0)
    }

    /// Request a background recount (debounced, see `run_recount_worker`).
    pub fn mark_dirty(&self) {
        self.dirty.notify_one();
    }

    /// Walk the data directory and reset `used` to the real on-disk size.
    /// In-flight temporary files (under `TMP_DIR`) are excluded: they are covered by reservations.
    ///
    /// Writes committed and deletions made while a walk is in progress may be
    /// counted once more until the next recount: the counter errs on the side of
    /// over-counting, never under-counting.
    pub async fn recount(&self, data_dir: &Path) {
        let _serialized = self.recount_lock.lock().await;
        {
            let mut state = self.lock();
            state.scanning = true;
            state.committed_during_scan = 0;
        }
        let dir = data_dir.to_path_buf();
        let scanned = tokio::task::spawn_blocking(move || data_dir_usage(&dir))
            .await
            .unwrap_or(0);
        let mut state = self.lock();
        state.used = scanned.saturating_add(state.committed_during_scan);
        state.scanning = false;
        state.committed_during_scan = 0;
    }

    /// Background task: recount whenever the counter is marked dirty, at most
    /// once per `RECOUNT_DEBOUNCE`.
    pub async fn run_recount_worker(self: Arc<Self>, data_dir: PathBuf) {
        loop {
            self.dirty.notified().await;
            tokio::time::sleep(RECOUNT_DEBOUNCE).await;
            self.recount(&data_dir).await;
        }
    }
}

/// Bytes reserved by one in-flight write. Dropping it without `commit` releases
/// the reservation (failed or interrupted upload).
pub struct Reservation {
    quota: Arc<Quota>,
    factor: u64,
    reserved: u64,
    committed: bool,
}

impl Reservation {
    /// Make sure at least `payload_bytes` (before applying the copy factor) are reserved.
    pub fn ensure(&mut self, payload_bytes: u64) -> Result<(), S3Error> {
        let needed = payload_bytes.saturating_mul(self.factor);
        if needed == 0 && self.reserved == 0 {
            // Even an empty write is refused once the quota is exceeded
            return self.quota.check_not_exceeded();
        }
        if needed > self.reserved {
            let extra = needed - self.reserved;
            self.quota.try_reserve(extra)?;
            self.reserved = needed;
        }
        Ok(())
    }

    /// Convert the reservation into used bytes. `payload_bytes` is the size
    /// actually written (the copy factor is applied).
    pub fn commit(mut self, payload_bytes: u64) {
        let actual = payload_bytes.saturating_mul(self.factor);
        self.quota.commit_reservation(self.reserved, actual);
        self.committed = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed && self.reserved > 0 {
            self.quota.release_reservation(self.reserved);
        }
    }
}

/// Apparent size of all regular files under `path` (symlinks are not followed).
pub fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    walk_files(path, &mut |_, meta| {
        total = total.saturating_add(meta.len())
    });
    total
}

/// Storage usage of the data directory: every file except in-flight temporary
/// files under `TMP_DIR` (those are covered by reservations).
pub fn data_dir_usage(data_dir: &Path) -> u64 {
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        if entry.file_name() == TMP_DIR {
            continue;
        }
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {}
            Ok(m) if m.is_dir() => total = total.saturating_add(dir_size(&path)),
            Ok(m) if m.is_file() => total = total.saturating_add(m.len()),
            _ => {}
        }
    }
    total
}

/// Call `f` for every regular file under `path`, without following symlinks.
fn walk_files(path: &Path, f: &mut impl FnMut(&Path, &std::fs::Metadata)) {
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let meta = match std::fs::symlink_metadata(&entry_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_files(&entry_path, f);
        } else if meta.is_file() {
            f(&entry_path, &meta);
        }
    }
}

/// Size of a regular file, 0 if it does not exist.
pub async fn file_size(path: &Path) -> u64 {
    match tokio::fs::symlink_metadata(path).await {
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    }
}

/// Remove leftover temporary files. Called once at startup, before serving
/// requests: any file left under `TMP_DIR` at that point belongs to a write
/// interrupted by a crash or a shutdown. Nothing outside `TMP_DIR` is touched,
/// so objects whose key ends in `.tmp` are safe.
/// Returns (files removed, bytes freed).
pub fn remove_stale_tmp_files(data_dir: &Path) -> (u64, u64) {
    let (mut count, mut bytes) = (0u64, 0u64);
    walk_files(&data_dir.join(TMP_DIR), &mut |path, meta| {
        if std::fs::remove_file(path).is_ok() {
            count += 1;
            bytes += meta.len();
        }
    });
    (count, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_always_reserves() {
        let q = Arc::new(Quota::unlimited());
        let mut r = q.reservation(1);
        assert!(r.ensure(u64::MAX / 2).is_ok());
        r.commit(10);
        assert_eq!(q.usage().used_bytes, 10);
        assert_eq!(q.usage().reserved_bytes, 0);
    }

    #[test]
    fn test_limit_enforced_across_reservations() {
        let q = Arc::new(Quota::new(Some(100)));
        let mut a = q.reservation(1);
        let mut b = q.reservation(1);
        assert!(a.ensure(60).is_ok());
        assert!(matches!(b.ensure(50), Err(S3Error::QuotaExceeded)));
        assert!(b.ensure(40).is_ok());
        drop(a); // failed upload releases its bytes
        assert_eq!(q.usage().reserved_bytes, 40);
        b.commit(40);
        assert_eq!(q.usage().used_bytes, 40);
    }

    #[test]
    fn test_factor_doubles_reservation() {
        let q = Arc::new(Quota::new(Some(100)));
        let mut r = q.reservation(2);
        assert!(r.ensure(50).is_ok());
        assert!(r.ensure(51).is_err());
        r.commit(50);
        assert_eq!(q.usage().used_bytes, 100);
    }

    #[test]
    fn test_release_and_check() {
        let q = Arc::new(Quota::new(Some(10)));
        q.add(15);
        assert!(q.check_not_exceeded().is_err());
        q.release(10);
        assert!(q.check_not_exceeded().is_ok());
        q.release(100);
        assert_eq!(q.usage().used_bytes, 0);
    }
}
