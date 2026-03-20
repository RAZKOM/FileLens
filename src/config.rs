use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub window_width: f32,
    pub window_height: f32,
    pub last_tab: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            window_width: 520.0,
            window_height: 480.0,
            last_tab: 0,
        }
    }
}

impl AppConfig {
    /// Get the config file path (next to the exe).
    fn config_path() -> Option<PathBuf> {
        std::env::current_exe().ok().map(|p| p.with_file_name("filelens_config.json"))
    }

    /// Load config from disk, or return default.
    pub fn load() -> Self {
        Self::config_path()
            .and_then(|path| std::fs::read_to_string(&path).ok())
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    }

    /// Save config to disk.
    pub fn save(&self) {
        if let Some(path) = Self::config_path() {
            if let Ok(json) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(&path, json);
            }
        }
    }
}
