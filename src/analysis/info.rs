use super::AnalysisTab;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug, Default)]
pub struct FileInfo {
    pub size_bytes: u64,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub timestamp_anomaly: bool,
    pub magic_hex: String,
    pub detected_type: String,
    pub extension: String,
    pub type_mismatch: bool,
    pub entropy: f64,
    pub pe_info: Option<PeInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct PeInfo {
    pub architecture: String,
    pub subsystem: String,
    pub num_sections: u16,
    pub num_imports: usize,
    pub num_exports: usize,
    pub is_signed: bool,
    pub compile_timestamp: String,
    pub compile_ts_raw: u32,
    pub compile_ts_warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InfoState {
    pub info: Option<FileInfo>,
    pub error: Option<String>,
    pub done: bool,
}

pub struct InfoTab {
    state: Arc<Mutex<InfoState>>,
    started: bool,
    cancel: Arc<AtomicBool>,
}

impl InfoTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(InfoState {
                info: None,
                error: None,
                done: false,
            })),
            started: false,
            cancel,
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB ({bytes} B)", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB ({bytes} B)", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!(
            "{:.2} GB ({bytes} B)",
            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        )
    }
}

fn format_system_time(st: std::io::Result<std::time::SystemTime>) -> Option<String> {
    let t = st.ok()?;
    let duration = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    let dt = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)?;
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Shannon entropy of a byte slice. Range 0.0 (uniform) to 8.0 (max randomness).
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn detect_mime_type(magic: &[u8]) -> &'static str {
    if magic.len() < 2 {
        return "unknown";
    }
    if magic[0] == 0x4D && magic[1] == 0x5A {
        return "application/x-dosexec (PE)";
    }
    if magic.len() >= 4 && &magic[0..4] == b"%PDF" {
        return "application/pdf";
    }
    if magic.len() >= 8 && &magic[0..8] == b"\x89PNG\r\n\x1a\n" {
        return "image/png";
    }
    if magic[0] == 0xFF && magic[1] == 0xD8 {
        return "image/jpeg";
    }
    if magic.len() >= 3 && &magic[0..3] == b"GIF" {
        return "image/gif";
    }
    if magic[0] == 0x50 && magic[1] == 0x4B {
        return "application/zip";
    }
    if magic[0] == 0x1F && magic[1] == 0x8B {
        return "application/gzip";
    }
    if magic[0] == 0x42 && magic[1] == 0x4D {
        return "image/bmp";
    }
    if magic.len() >= 4 && &magic[0..4] == b"RIFF" {
        return "application/x-riff";
    }
    if magic.len() >= 6 && &magic[0..6] == b"SQLite" {
        return "application/x-sqlite3";
    }
    "unknown"
}

fn extension_matches_type(ext: &str, detected: &str) -> bool {
    match ext.to_lowercase().as_str() {
        "exe" | "dll" | "sys" | "scr" | "ocx" => detected.contains("dosexec"),
        "pdf" => detected.contains("pdf"),
        "png" => detected.contains("png"),
        "jpg" | "jpeg" => detected.contains("jpeg"),
        "gif" => detected.contains("gif"),
        "zip" | "docx" | "xlsx" | "pptx" | "jar" | "apk" => detected.contains("zip"),
        "gz" | "gzip" | "tgz" => detected.contains("gzip"),
        "bmp" => detected.contains("bmp"),
        "wav" | "avi" | "webp" => detected.contains("riff"),
        "db" | "sqlite" | "sqlite3" => detected.contains("sqlite"),
        _ => true,
    }
}

pub fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

pub fn rva_to_offset(
    data: &[u8],
    pe_offset: usize,
    num_sections: u16,
    rva: u32,
) -> Option<usize> {
    let coff_offset = pe_offset + 4;
    let optional_hdr_size = read_u16_le(data, coff_offset + 16) as usize;
    let section_table_offset = coff_offset + 20 + optional_hdr_size;

    for i in 0..num_sections as usize {
        let sec_offset = section_table_offset + i * 40;
        if sec_offset + 40 > data.len() {
            break;
        }
        let virtual_size = read_u32_le(data, sec_offset + 8);
        let virtual_addr = read_u32_le(data, sec_offset + 12);
        let raw_size = read_u32_le(data, sec_offset + 16);
        let raw_offset = read_u32_le(data, sec_offset + 20);

        let section_end = virtual_addr + std::cmp::max(virtual_size, raw_size);
        if rva >= virtual_addr && rva < section_end {
            return Some((rva - virtual_addr + raw_offset) as usize);
        }
    }
    None
}

fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return None;
    }

    let pe_offset = read_u32_le(data, 0x3C) as usize;
    if pe_offset + 24 > data.len() {
        return None;
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let coff_offset = pe_offset + 4;
    let machine = read_u16_le(data, coff_offset);
    let num_sections = read_u16_le(data, coff_offset + 2);
    let timestamp_raw = read_u32_le(data, coff_offset + 4);

    let architecture = match machine {
        0x014C => "x86 (i386)".into(),
        0x8664 => "x64 (AMD64)".into(),
        0xAA64 => "ARM64".into(),
        0x01C0 => "ARM".into(),
        other => format!("Unknown (0x{other:04X})"),
    };

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    let compile_timestamp = if timestamp_raw > 0 {
        chrono::DateTime::from_timestamp(timestamp_raw as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("0x{timestamp_raw:08X}"))
    } else {
        "N/A".into()
    };

    let compile_ts_warning = if timestamp_raw > now_ts && timestamp_raw > 0 {
        Some("Future timestamp!".into())
    } else if timestamp_raw > 0 && timestamp_raw < 946684800 {
        Some("Before year 2000 — suspiciously old".into())
    } else {
        None
    };

    let opt_offset = coff_offset + 20;
    let opt_magic = read_u16_le(data, opt_offset);

    let subsystem = if (opt_magic == 0x10B || opt_magic == 0x20B) && opt_offset + 70 <= data.len()
    {
        match read_u16_le(data, opt_offset + 68) {
            0 => "Unknown".into(),
            1 => "Native".into(),
            2 => "Windows GUI".into(),
            3 => "Windows Console".into(),
            5 => "OS/2 Console".into(),
            7 => "POSIX Console".into(),
            9 => "Windows CE GUI".into(),
            10 => "EFI Application".into(),
            11 => "EFI Boot Service Driver".into(),
            12 => "EFI Runtime Driver".into(),
            13 => "EFI ROM".into(),
            14 => "Xbox".into(),
            16 => "Windows Boot Application".into(),
            other => format!("Unknown ({other})"),
        }
    } else {
        "N/A".into()
    };

    let (num_data_dirs_offset, data_dir_start) = match opt_magic {
        0x10B => (opt_offset + 92, opt_offset + 96),
        0x20B => (opt_offset + 108, opt_offset + 112),
        _ => (0, 0),
    };

    let mut num_imports = 0;
    let mut num_exports = 0;

    if data_dir_start > 0 && num_data_dirs_offset + 4 <= data.len() {
        let num_data_dirs = read_u32_le(data, num_data_dirs_offset) as usize;

        if num_data_dirs > 0 && data_dir_start + 8 <= data.len() {
            let export_rva = read_u32_le(data, data_dir_start);
            let export_size = read_u32_le(data, data_dir_start + 4);
            if export_rva > 0 && export_size > 0 {
                if let Some(offset) =
                    rva_to_offset(data, pe_offset, num_sections, export_rva)
                {
                    if offset + 24 <= data.len() {
                        num_exports = read_u32_le(data, offset + 24) as usize;
                    }
                }
            }
        }

        if num_data_dirs > 1 && data_dir_start + 16 <= data.len() {
            let import_rva = read_u32_le(data, data_dir_start + 8);
            if import_rva > 0 {
                if let Some(offset) =
                    rva_to_offset(data, pe_offset, num_sections, import_rva)
                {
                    let mut pos = offset;
                    while pos + 20 <= data.len() {
                        if read_u32_le(data, pos + 12) == 0 {
                            break;
                        }
                        num_imports += 1;
                        pos += 20;
                    }
                }
            }
        }
    }

    let is_signed = if data_dir_start > 0 {
        let num_data_dirs = read_u32_le(data, num_data_dirs_offset) as usize;
        if num_data_dirs > 4 {
            let cert_rva = read_u32_le(data, data_dir_start + 4 * 8);
            let cert_size = read_u32_le(data, data_dir_start + 4 * 8 + 4);
            cert_rva > 0 && cert_size > 0
        } else {
            false
        }
    } else {
        false
    };

    Some(PeInfo {
        architecture,
        subsystem,
        num_sections,
        num_imports,
        num_exports,
        is_signed,
        compile_timestamp,
        compile_ts_raw: timestamp_raw,
        compile_ts_warning,
    })
}

fn analyze_file(path: &Path, cancel: &AtomicBool) -> Result<FileInfo, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("Cannot read metadata: {e}"))?;

    let size_bytes = metadata.len();
    let created = format_system_time(metadata.created());
    let modified = format_system_time(metadata.modified());
    let accessed = format_system_time(metadata.accessed());

    let timestamp_anomaly = match (metadata.modified(), metadata.created()) {
        (Ok(m), Ok(c)) => m < c,
        _ => false,
    };

    let data = std::fs::read(path).map_err(|e| format!("Cannot read file: {e}"))?;
    if cancel.load(Ordering::Relaxed) {
        return Err("Cancelled".into());
    }

    let magic_len = std::cmp::min(16, data.len());
    let magic_bytes = &data[..magic_len];
    let magic_hex = magic_bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");

    let detected_type = detect_mime_type(magic_bytes).to_string();

    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    let type_mismatch = !extension.is_empty()
        && detected_type != "unknown"
        && !extension_matches_type(&extension, &detected_type);

    let entropy = compute_entropy(&data);

    let pe_info = if detected_type.contains("dosexec") {
        parse_pe(&data)
    } else {
        None
    };

    Ok(FileInfo {
        size_bytes,
        created,
        modified,
        accessed,
        timestamp_anomaly,
        magic_hex,
        detected_type,
        extension,
        type_mismatch,
        entropy,
        pe_info,
    })
}

impl AnalysisTab for InfoTab {
    fn name(&self) -> &str {
        "Info"
    }

    fn run(&mut self, path: &Path) {
        if self.started {
            return;
        }
        self.started = true;

        let path = path.to_path_buf();
        let state = self.state.clone();
        let cancel = self.cancel.clone();

        thread::spawn(move || {
            match analyze_file(&path, &cancel) {
                Ok(info) => {
                    let mut s = state.lock().unwrap();
                    s.info = Some(info);
                    s.done = true;
                }
                Err(e) => {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut s = state.lock().unwrap();
                    s.error = Some(e);
                    s.done = true;
                }
            }
        });
    }

    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let state = self.state.lock().unwrap().clone();

        if !state.done {
            ctx.request_repaint();
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Analyzing...");
            });
            return;
        }

        if let Some(ref err) = state.error {
            ui.label(
                egui::RichText::new(err).color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
            );
            return;
        }

        let info = match &state.info {
            Some(i) => i,
            None => return,
        };

        ui.add_space(2.0);

        let label_color = egui::Color32::from_rgb(0x66, 0x66, 0x66);
        let value_color = egui::Color32::from_rgb(0xCC, 0xCC, 0xCC);
        let warn_color = egui::Color32::from_rgb(0xCC, 0x22, 0x22);

        fn info_row(
            ui: &mut egui::Ui,
            label: &str,
            value: &str,
            color: egui::Color32,
            label_color: egui::Color32,
        ) {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(label)
                        .strong()
                        .size(11.0)
                        .color(label_color),
                );
                ui.label(egui::RichText::new(value).size(11.0).color(color));
            });
        }

        info_row(ui, "Size:", &format_size(info.size_bytes), value_color, label_color);

        if let Some(ref val) = info.created {
            info_row(ui, "Created:", val, value_color, label_color);
        }
        if let Some(ref val) = info.modified {
            let color = if info.timestamp_anomaly {
                warn_color
            } else {
                value_color
            };
            info_row(ui, "Modified:", val, color, label_color);
        }
        if info.timestamp_anomaly {
            ui.label(
                egui::RichText::new("  \u{26A0} Modified < Created")
                    .size(10.0)
                    .color(warn_color),
            );
        }
        if let Some(ref val) = info.accessed {
            info_row(ui, "Accessed:", val, value_color, label_color);
        }

        let entropy_color = if info.entropy > 7.5 {
            warn_color
        } else if info.entropy > 6.5 {
            egui::Color32::from_rgb(0xE0, 0xA0, 0x40)
        } else {
            value_color
        };
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Entropy:")
                    .strong()
                    .size(11.0)
                    .color(label_color),
            );
            ui.label(
                egui::RichText::new(format!("{:.3} / 8.0", info.entropy))
                    .size(11.0)
                    .color(entropy_color),
            );
            if info.entropy > 7.5 {
                ui.label(
                    egui::RichText::new("(packed/encrypted?)")
                        .size(10.0)
                        .color(warn_color),
                );
            } else if info.entropy > 6.5 {
                ui.label(
                    egui::RichText::new("(compressed?)")
                        .size(10.0)
                        .color(egui::Color32::from_rgb(0xE0, 0xA0, 0x40)),
                );
            }
        });

        ui.add_space(2.0);
        ui.separator();
        ui.add_space(1.0);

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("Magic:")
                    .strong()
                    .size(11.0)
                    .color(label_color),
            );
            ui.label(
                egui::RichText::new(&info.magic_hex)
                    .monospace()
                    .size(10.0)
                    .color(value_color),
            );
        });

        info_row(ui, "Type:", &info.detected_type, value_color, label_color);

        if !info.extension.is_empty() {
            info_row(
                ui,
                "Ext:",
                &format!(".{}", info.extension),
                value_color,
                label_color,
            );
        }

        if info.type_mismatch {
            ui.label(
                egui::RichText::new("  \u{26A0} Extension/type mismatch!")
                    .size(10.0)
                    .color(warn_color),
            );
        }

        if let Some(ref pe) = info.pe_info {
            ui.add_space(2.0);
            ui.separator();
            ui.label(
                egui::RichText::new("PE Information")
                    .strong()
                    .size(11.0)
                    .color(warn_color),
            );
            ui.add_space(1.0);

            info_row(ui, "Arch:", &pe.architecture, value_color, label_color);
            info_row(ui, "Subsystem:", &pe.subsystem, value_color, label_color);
            info_row(
                ui,
                "Sections:",
                &pe.num_sections.to_string(),
                value_color,
                label_color,
            );
            info_row(
                ui,
                "Imports:",
                &pe.num_imports.to_string(),
                value_color,
                label_color,
            );
            info_row(
                ui,
                "Exports:",
                &pe.num_exports.to_string(),
                value_color,
                label_color,
            );
            info_row(
                ui,
                "Signed:",
                if pe.is_signed { "Yes" } else { "No" },
                if pe.is_signed {
                    egui::Color32::from_rgb(0x80, 0xD0, 0x80)
                } else {
                    value_color
                },
                label_color,
            );

            let ts_color = if pe.compile_ts_warning.is_some() {
                warn_color
            } else {
                value_color
            };
            info_row(ui, "Compiled:", &pe.compile_timestamp, ts_color, label_color);

            if let Some(ref warning) = pe.compile_ts_warning {
                ui.label(
                    egui::RichText::new(format!("  \u{26A0} {warning}"))
                        .size(10.0)
                        .color(warn_color),
                );
            }
        }
    }

    fn is_loading(&self) -> bool {
        !self.state.lock().unwrap().done
    }
}