//! Clean Rust module — should produce zero findings.
//! Demonstrates proper practices: ? operator instead of unwrap,
//! no unsafe blocks, descriptive error handling throughout.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Configuration loaded from a file.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub settings: HashMap<String, String>,
}

impl Config {
    /// Load configuration from a TOML-like key=value file.
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut settings = HashMap::new();
        let mut host = String::from("0.0.0.0");
        let mut port: u16 = 8080;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "host" => host = value.to_string(),
                    "port" => {
                        port = value.parse().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("bad port: {e}"))
                        })?;
                    }
                    _ => {
                        settings.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        Ok(Config {
            host,
            port,
            settings,
        })
    }

    /// Get a setting by key, returning None if not found.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.settings.get(key).map(|s| s.as_str())
    }

    /// Return the bind address as "host:port".
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Process a batch of items, collecting results and errors.
pub fn process_batch(items: &[String]) -> (Vec<String>, Vec<String>) {
    let mut successes = Vec::new();
    let mut errors = Vec::new();

    for item in items {
        match validate_item(item) {
            Ok(result) => successes.push(result),
            Err(msg) => errors.push(format!("item '{}': {}", item, msg)),
        }
    }

    (successes, errors)
}

fn validate_item(item: &str) -> Result<String, &'static str> {
    if item.is_empty() {
        return Err("empty item");
    }
    if item.len() > 100 {
        return Err("item too long");
    }
    Ok(item.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_item_ok() {
        let result = validate_item("hello").unwrap(); // unwrap OK in tests
        assert_eq!(result, "HELLO");
    }

    #[test]
    fn test_validate_empty_item() {
        assert!(validate_item("").is_err());
    }
}
