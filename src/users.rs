use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::auth::Credentials;
use crate::error::S3Error;

/// A user record stored in the users JSON file.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub user_id: String,
    pub display_name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub is_root: bool,
}

/// JSON file format for the users store.
#[derive(Serialize, Deserialize)]
struct UsersFile {
    users: Vec<UserRecord>,
}

/// In-memory user store backed by a JSON file on disk.
pub struct UserStore {
    by_access_key: HashMap<String, UserRecord>,
    by_user_id: HashMap<String, UserRecord>,
    file_path: Option<PathBuf>,
}

impl UserStore {
    /// Load users from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read users file '{}': {}", path.display(), e))?;
        let file: UsersFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse users file '{}': {}", path.display(), e))?;

        Self::from_records(file.users, Some(path.to_path_buf()))
    }

    /// Create a store from a single set of env-var credentials (backward compat).
    /// The synthetic user is root. No file_path means the admin API is disabled.
    pub fn from_single_credentials(creds: Credentials) -> Self {
        let record = UserRecord {
            user_id: "root".to_string(),
            display_name: "Root".to_string(),
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            is_root: true,
        };

        let mut by_access_key = HashMap::new();
        let mut by_user_id = HashMap::new();
        by_access_key.insert(record.access_key_id.clone(), record.clone());
        by_user_id.insert(record.user_id.clone(), record);

        Self {
            by_access_key,
            by_user_id,
            file_path: None,
        }
    }

    fn from_records(records: Vec<UserRecord>, file_path: Option<PathBuf>) -> Result<Self, String> {
        if records.is_empty() {
            return Err("Users file must contain at least one user".to_string());
        }

        let root_count = records.iter().filter(|r| r.is_root).count();
        if root_count != 1 {
            return Err(format!(
                "Users file must contain exactly one root user, found {}",
                root_count
            ));
        }

        let mut by_access_key = HashMap::new();
        let mut by_user_id = HashMap::new();

        for record in records {
            if record.user_id.is_empty() {
                return Err("User ID must not be empty".to_string());
            }
            if record.access_key_id.is_empty() || record.secret_access_key.is_empty() {
                return Err(format!(
                    "User '{}' has empty access_key_id or secret_access_key",
                    record.user_id
                ));
            }
            if by_user_id.contains_key(&record.user_id) {
                return Err(format!("Duplicate user_id: '{}'", record.user_id));
            }
            if by_access_key.contains_key(&record.access_key_id) {
                return Err(format!(
                    "Duplicate access_key_id: '{}'",
                    record.access_key_id
                ));
            }
            by_user_id.insert(record.user_id.clone(), record.clone());
            by_access_key.insert(record.access_key_id.clone(), record);
        }

        Ok(Self {
            by_access_key,
            by_user_id,
            file_path,
        })
    }

    /// Look up a user by their access key ID.
    pub fn lookup_by_access_key(&self, access_key_id: &str) -> Option<&UserRecord> {
        self.by_access_key.get(access_key_id)
    }

    /// Look up a user by their user ID.
    pub fn get_user(&self, user_id: &str) -> Option<&UserRecord> {
        self.by_user_id.get(user_id)
    }

    /// List all users.
    pub fn list_users(&self) -> Vec<&UserRecord> {
        let mut users: Vec<&UserRecord> = self.by_user_id.values().collect();
        users.sort_by_key(|u| &u.user_id);
        users
    }

    /// Add or update a user. Validates uniqueness. Persists to file.
    pub async fn add_user(&mut self, record: UserRecord) -> Result<(), S3Error> {
        if record.user_id.is_empty() {
            return Err(S3Error::InvalidArgument("user_id must not be empty".to_string()));
        }
        if record.access_key_id.is_empty() || record.secret_access_key.is_empty() {
            return Err(S3Error::InvalidArgument(
                "access_key_id and secret_access_key must not be empty".to_string(),
            ));
        }

        // Cannot create a second root user or change root status
        if record.is_root {
            let existing_root = self.by_user_id.values().find(|u| u.is_root);
            if let Some(root) = existing_root {
                if root.user_id != record.user_id {
                    return Err(S3Error::InvalidArgument(
                        "Cannot create a second root user".to_string(),
                    ));
                }
            }
        }

        // Check access_key_id uniqueness (allow if it's the same user being updated)
        if let Some(existing) = self.by_access_key.get(&record.access_key_id) {
            if existing.user_id != record.user_id {
                return Err(S3Error::InvalidArgument(format!(
                    "access_key_id '{}' is already in use by user '{}'",
                    record.access_key_id, existing.user_id
                )));
            }
        }

        // If updating, remove old access key mapping
        if let Some(old) = self.by_user_id.get(&record.user_id) {
            self.by_access_key.remove(&old.access_key_id);
        }

        self.by_access_key
            .insert(record.access_key_id.clone(), record.clone());
        self.by_user_id
            .insert(record.user_id.clone(), record);

        self.save_to_file().await?;
        Ok(())
    }

    /// Delete a user by user_id. Cannot delete root. Persists to file.
    pub async fn delete_user(&mut self, user_id: &str) -> Result<(), S3Error> {
        let record = self
            .by_user_id
            .get(user_id)
            .ok_or(S3Error::InvalidArgument(format!(
                "User '{}' not found",
                user_id
            )))?;

        if record.is_root {
            return Err(S3Error::InvalidArgument(
                "Cannot delete the root user".to_string(),
            ));
        }

        let access_key = record.access_key_id.clone();
        self.by_user_id.remove(user_id);
        self.by_access_key.remove(&access_key);

        self.save_to_file().await?;
        Ok(())
    }

    /// Whether this store has a backing file (and thus supports the admin API).
    pub fn has_file(&self) -> bool {
        self.file_path.is_some()
    }

    /// Persist the current state to the JSON file (atomic: tmp + rename).
    async fn save_to_file(&self) -> Result<(), S3Error> {
        let path = self
            .file_path
            .as_ref()
            .ok_or_else(|| S3Error::InternalError("No file path configured".to_string()))?;

        let users: Vec<UserRecord> = {
            let mut users: Vec<UserRecord> = self.by_user_id.values().cloned().collect();
            users.sort_by(|a, b| a.user_id.cmp(&b.user_id));
            users
        };

        let file = UsersFile { users };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        // Write with restrictive permissions (0600) to protect secrets
        tokio::task::spawn_blocking({
            let tmp = tmp_path.clone();
            let data = json.into_bytes();
            move || write_file_restricted(&tmp, &data)
        })
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?
        .map_err(|e| S3Error::InternalError(e.to_string()))?;
        tokio::fs::rename(&tmp_path, path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Return the number of users in the store.
    pub fn len(&self) -> usize {
        self.by_user_id.len()
    }

    /// Build the ARN for a user.
    pub fn arn_for(user_id: &str) -> String {
        format!("arn:loch:iam:::user/{}", user_id)
    }

    /// Bootstrap a new users file with a generated root user.
    /// Returns the store and the generated credentials (for logging).
    pub fn bootstrap(path: &Path) -> Result<(Self, String, String), String> {
        let access_key_id = generate_key(20);
        let secret_access_key = generate_key(40);

        let record = UserRecord {
            user_id: "root".to_string(),
            display_name: "Root".to_string(),
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            is_root: true,
        };

        let file = UsersFile {
            users: vec![record.clone()],
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| format!("Failed to serialize users file: {}", e))?;

        // Write atomically via tmp + rename, with restrictive permissions (0600)
        let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        write_file_restricted(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Failed to write users file '{}': {}", tmp_path.display(), e))?;
        std::fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to rename users file: {}", e))?;

        let store = Self::from_records(vec![record], Some(path.to_path_buf()))?;
        Ok((store, access_key_id, secret_access_key))
    }
}

/// Generate a random alphanumeric key of the given length (uniform, no modulo bias).
fn generate_key(len: usize) -> String {
    use rand::{Rng, RngExt};
    use rand::distr::Alphanumeric;
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Write data to a file with mode 0600 (owner read/write only).
fn write_file_restricted(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root() -> UserRecord {
        UserRecord {
            user_id: "admin".to_string(),
            display_name: "Admin".to_string(),
            access_key_id: "AKIAADMIN".to_string(),
            secret_access_key: "secret-admin".to_string(),
            is_root: true,
        }
    }

    fn make_user(id: &str) -> UserRecord {
        UserRecord {
            user_id: id.to_string(),
            display_name: id.to_string(),
            access_key_id: format!("AKIA{}", id.to_uppercase()),
            secret_access_key: format!("secret-{}", id),
            is_root: false,
        }
    }

    #[test]
    fn test_from_records_valid() {
        let records = vec![make_root(), make_user("alice")];
        let store = UserStore::from_records(records, None).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.lookup_by_access_key("AKIAADMIN").unwrap().is_root);
        assert_eq!(
            store.lookup_by_access_key("AKIAALICE").unwrap().user_id,
            "alice"
        );
    }

    #[test]
    fn test_from_records_no_root() {
        let records = vec![make_user("alice")];
        assert!(UserStore::from_records(records, None).is_err());
    }

    #[test]
    fn test_from_records_two_roots() {
        let mut root2 = make_user("bob");
        root2.is_root = true;
        let records = vec![make_root(), root2];
        assert!(UserStore::from_records(records, None).is_err());
    }

    #[test]
    fn test_from_records_duplicate_user_id() {
        let mut dup = make_root();
        dup.access_key_id = "AKIADIFFERENT".to_string();
        let records = vec![make_root(), dup];
        assert!(UserStore::from_records(records, None).is_err());
    }

    #[test]
    fn test_from_records_duplicate_access_key() {
        let mut dup = make_user("bob");
        dup.access_key_id = "AKIAADMIN".to_string();
        let records = vec![make_root(), dup];
        assert!(UserStore::from_records(records, None).is_err());
    }

    #[test]
    fn test_arn_for() {
        assert_eq!(
            UserStore::arn_for("alice"),
            "arn:loch:iam:::user/alice"
        );
    }

    #[test]
    fn test_from_single_credentials() {
        let creds = Credentials {
            access_key_id: "MYKEY".to_string(),
            secret_access_key: "MYSECRET".to_string(),
        };
        let store = UserStore::from_single_credentials(creds);
        assert_eq!(store.len(), 1);
        assert!(store.lookup_by_access_key("MYKEY").unwrap().is_root);
        assert!(!store.has_file());
    }

    #[test]
    fn test_list_users_sorted() {
        let records = vec![make_root(), make_user("zeta"), make_user("alpha")];
        let store = UserStore::from_records(records, None).unwrap();
        let users = store.list_users();
        let ids: Vec<&str> = users.iter().map(|u| u.user_id.as_str()).collect();
        assert_eq!(ids, vec!["admin", "alpha", "zeta"]);
    }
}
