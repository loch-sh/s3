use std::fs;
use std::path::Path;

use crate::storage::Storage;

pub fn get_bucket_size(storage: &Storage, name: &str) -> u64 {
    let path = match Storage::safe_bucket_path(storage, name) {
        Err(_) => return 0,
        Ok(p) => p,
    };

    dir_size(&path)
}

fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path());
        }
    }
    total
}
