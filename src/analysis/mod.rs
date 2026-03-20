use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub trait AnalysisTab: Send {
    fn name(&self) -> &str; // Tab label

    fn run(&mut self, path: &std::path::Path); // Start background work

    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context); // Draw tab contents

    fn is_loading(&self) -> bool; // Show spinner in tab bar

    fn relevant_for(&self, _path: &std::path::Path) -> bool { // Show/hide tab per file
        true
    }
}

pub mod hashes;
pub mod hex;
pub mod info;
pub mod metadata;
pub mod pe_details;
pub mod strings;

use std::path::Path;

pub fn create_tabs_for(path: &Path, cancel: Arc<AtomicBool>) -> Vec<Box<dyn AnalysisTab>> {
    let all: Vec<Box<dyn AnalysisTab>> = vec![
        Box::new(info::InfoTab::new(cancel.clone())),
        Box::new(hashes::HashesTab::new(cancel.clone())),
        Box::new(strings::StringsTab::new(cancel.clone())),
        Box::new(pe_details::PeDetailsTab::new(cancel.clone())),
        Box::new(hex::HexTab::new(cancel.clone())),
        Box::new(metadata::MetadataTab::new(cancel.clone())),
    ];

    all.into_iter()
        .filter(|tab| tab.relevant_for(path))
        .collect()
}

pub fn run_all(tabs: &mut [Box<dyn AnalysisTab>], path: &Path) {
    for tab in tabs.iter_mut() {
        tab.run(path);
    }
}

/// magic-byte detection
pub fn read_magic(path: &Path, n: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; n];
    let bytes_read = file.read(&mut buf).ok()?;
    buf.truncate(bytes_read);
    Some(buf)
}

/// (MZ header + PE\0\0 signature)
pub fn is_pe_file(path: &Path) -> bool {
    let Some(magic) = read_magic(path, 1024) else {
        return false;
    };
    if magic.len() < 64 || magic[0] != 0x4D || magic[1] != 0x5A {
        return false;
    }
    let pe_offset = info::read_u32_le(&magic, 0x3C) as usize;
    if pe_offset + 4 > magic.len() {
        return false;
    }
    &magic[pe_offset..pe_offset + 4] == b"PE\0\0"
}
 
/// (PDF, ZIP-based Office docs, JPEG, PNG)
pub fn has_extractable_metadata(path: &Path) -> bool {
    let Some(magic) = read_magic(path, 16) else {
        return false;
    };
    if magic.len() < 4 {
        return false;
    }

    if &magic[0..4] == b"%PDF" {
        return true;
    }
    if magic[0] == 0x50 && magic[1] == 0x4B {
        return true;
    }
    if magic[0] == 0xFF && magic[1] == 0xD8 {
        return true;
    }
    if magic.len() >= 8 && &magic[0..8] == b"\x89PNG\r\n\x1a\n" {
        return true;
    }

    false
}