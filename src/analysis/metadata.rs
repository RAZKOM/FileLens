use super::AnalysisTab;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct MetadataState {
    pub format_name: String,
    pub entries: Vec<MetadataEntry>,
    pub error: Option<String>,
    pub done: bool,
}

pub struct MetadataTab {
    state: Arc<Mutex<MetadataState>>,
    started: bool,
    cancel: Arc<AtomicBool>,
}

impl MetadataTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MetadataState {
                format_name: String::new(),
                entries: Vec::new(),
                error: None,
                done: false,
            })),
            started: false,
            cancel,
        }
    }
}

fn xml_value(text: &str, open_tag: &str, close_tag: &str) -> Option<String> {
    let start_pos = text.find(open_tag)?;
    let after_open = &text[start_pos + open_tag.len()..];

    let content_start = if open_tag.ends_with('>') {
        0
    } else {
        after_open.find('>')? + 1
    };

    let content = &after_open[content_start..];
    let end_pos = content.find(close_tag)?;
    let value = content[..end_pos].trim().to_string();

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn extract_pdf_metadata(data: &[u8]) -> Option<(String, Vec<MetadataEntry>)> {
    if data.len() < 5 || &data[0..5] != b"%PDF-" {
        return None;
    }

    let text = String::from_utf8_lossy(data);
    let mut entries = Vec::new();

    if let Some(end) = text[5..].find(|c: char| c == '\n' || c == '\r') {
        entries.push(MetadataEntry {
            key: "PDF Version".into(),
            value: format!("PDF {}", &text[5..5 + end]),
        });
    }

    let fields = [
        ("/Title", "Title"),
        ("/Author", "Author"),
        ("/Subject", "Subject"),
        ("/Keywords", "Keywords"),
        ("/Creator", "Creator"),
        ("/Producer", "Producer"),
        ("/CreationDate", "Created"),
        ("/ModDate", "Modified"),
    ];

    for (marker, label) in &fields {
        if let Some(pos) = text.find(marker) {
            let rest = &text[pos + marker.len()..];
            if let Some(paren_start) = rest.find('(') {
                if let Some(paren_end) = rest[paren_start + 1..].find(')') {
                    let val = &rest[paren_start + 1..paren_start + 1 + paren_end];
                    if !val.is_empty() {
                        entries.push(MetadataEntry {
                            key: label.to_string(),
                            value: val.to_string(),
                        });
                    }
                }
            }
        }
    }

    let page_count = text
        .matches("/Type /Page")
        .count()
        .saturating_sub(text.matches("/Type /Pages").count());
    if page_count > 0 {
        entries.push(MetadataEntry {
            key: "Pages (approx)".into(),
            value: page_count.to_string(),
        });
    }

    if entries.is_empty() {
        None
    } else {
        Some(("PDF Document".into(), entries))
    }
}

fn extract_zip_metadata(data: &[u8]) -> Option<(String, Vec<MetadataEntry>)> {
    if data.len() < 4 || data[0] != 0x50 || data[1] != 0x4B {
        return None;
    }

    let text = String::from_utf8_lossy(data);

    let format = if text.contains("word/document.xml") || text.contains("word/") {
        "Microsoft Word (DOCX)"
    } else if text.contains("xl/workbook.xml") || text.contains("xl/") {
        "Microsoft Excel (XLSX)"
    } else if text.contains("ppt/presentation.xml") || text.contains("ppt/") {
        "Microsoft PowerPoint (PPTX)"
    } else {
        return None;
    };

    let mut entries = Vec::new();

    let xml_fields: &[(&str, &str, &str)] = &[
        ("<dc:creator>", "</dc:creator>", "Author"),
        ("<dc:title>", "</dc:title>", "Title"),
        ("<dc:description>", "</dc:description>", "Description"),
        (
            "<cp:lastModifiedBy>",
            "</cp:lastModifiedBy>",
            "Last Modified By",
        ),
        ("<cp:revision>", "</cp:revision>", "Revision"),
        ("<dcterms:created", "</dcterms:created>", "Created"),
        ("<dcterms:modified", "</dcterms:modified>", "Modified"),
        ("<Application>", "</Application>", "Application"),
    ];

    for (open, close, label) in xml_fields {
        if let Some(value) = xml_value(&text, open, close) {
            entries.push(MetadataEntry {
                key: label.to_string(),
                value,
            });
        }
    }

    Some((format.into(), entries))
}

fn extract_jpeg_metadata(data: &[u8]) -> Option<(String, Vec<MetadataEntry>)> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }

    let mut entries = vec![MetadataEntry {
        key: "Format".into(),
        value: "JPEG".into(),
    }];

    let mut pos = 2;
    while pos + 4 < data.len() {
        if data[pos] != 0xFF {
            break;
        }
        let marker = data[pos + 1];
        let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if marker == 0xE1 && pos + 10 < data.len() {
            if &data[pos + 4..pos + 10] == b"Exif\0\0" {
                entries.push(MetadataEntry {
                    key: "EXIF".into(),
                    value: "Present".into(),
                });

                if pos + 18 < data.len() {
                    let byte_order = if &data[pos + 10..pos + 12] == b"MM" {
                        "Big Endian (Motorola)"
                    } else {
                        "Little Endian (Intel)"
                    };
                    entries.push(MetadataEntry {
                        key: "Byte Order".into(),
                        value: byte_order.into(),
                    });
                }
            }
        }

        if (marker == 0xC0 || marker == 0xC2) && pos + 9 < data.len() {
            let height = u16::from_be_bytes([data[pos + 5], data[pos + 6]]);
            let width = u16::from_be_bytes([data[pos + 7], data[pos + 8]]);
            entries.push(MetadataEntry {
                key: "Dimensions".into(),
                value: format!("{width} x {height}"),
            });
            let components = data[pos + 9];
            entries.push(MetadataEntry {
                key: "Components".into(),
                value: components.to_string(),
            });
        }

        pos += 2 + seg_len;
    }

    if entries.len() <= 1 {
        None
    } else {
        Some(("JPEG Image".into(), entries))
    }
}

fn extract_png_metadata(data: &[u8]) -> Option<(String, Vec<MetadataEntry>)> {
    if data.len() < 24 || &data[0..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }

    let mut entries = vec![MetadataEntry {
        key: "Format".into(),
        value: "PNG".into(),
    }];

    if &data[12..16] == b"IHDR" && data.len() >= 29 {
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let bit_depth = data[24];
        let color_type = data[25];

        entries.push(MetadataEntry {
            key: "Dimensions".into(),
            value: format!("{width} x {height}"),
        });
        entries.push(MetadataEntry {
            key: "Bit Depth".into(),
            value: bit_depth.to_string(),
        });

        let color_name = match color_type {
            0 => "Grayscale",
            2 => "RGB",
            3 => "Indexed",
            4 => "Grayscale + Alpha",
            6 => "RGBA",
            _ => "Unknown",
        };
        entries.push(MetadataEntry {
            key: "Color Type".into(),
            value: color_name.into(),
        });
    }

    let mut pos = 8;
    while pos + 12 < data.len() {
        let chunk_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];

        if chunk_type == b"tEXt" && pos + 8 + chunk_len <= data.len() {
            let chunk_data = &data[pos + 8..pos + 8 + chunk_len];
            if let Some(null_pos) = chunk_data.iter().position(|&b| b == 0) {
                let key = String::from_utf8_lossy(&chunk_data[..null_pos]).to_string();
                let val = String::from_utf8_lossy(&chunk_data[null_pos + 1..]).to_string();
                entries.push(MetadataEntry { key, value: val });
            }
        }

        pos += 12 + chunk_len;
    }

    Some(("PNG Image".into(), entries))
}

fn analyze_metadata(path: &Path, cancel: &AtomicBool) -> MetadataState {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return MetadataState {
                format_name: String::new(),
                entries: Vec::new(),
                error: Some(format!("Read error: {e}")),
                done: true,
            }
        }
    };

    if cancel.load(Ordering::Relaxed) {
        return MetadataState {
            format_name: String::new(),
            entries: Vec::new(),
            error: None,
            done: true,
        };
    }

    if let Some((fmt, entries)) = extract_pdf_metadata(&data) {
        return MetadataState {
            format_name: fmt,
            entries,
            error: None,
            done: true,
        };
    }
    if let Some((fmt, entries)) = extract_zip_metadata(&data) {
        return MetadataState {
            format_name: fmt,
            entries,
            error: None,
            done: true,
        };
    }
    if let Some((fmt, entries)) = extract_jpeg_metadata(&data) {
        return MetadataState {
            format_name: fmt,
            entries,
            error: None,
            done: true,
        };
    }
    if let Some((fmt, entries)) = extract_png_metadata(&data) {
        return MetadataState {
            format_name: fmt,
            entries,
            error: None,
            done: true,
        };
    }

    MetadataState {
        format_name: "Unknown".into(),
        entries: Vec::new(),
        error: None,
        done: true,
    }
}

impl AnalysisTab for MetadataTab {
    fn name(&self) -> &str {
        "Meta"
    }

    fn relevant_for(&self, path: &std::path::Path) -> bool {
        super::has_extractable_metadata(path)
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
            let result = analyze_metadata(&path, &cancel);
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            *state.lock().unwrap() = result;
        });
    }

    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let state = self.state.lock().unwrap().clone();

        if !state.done {
            ctx.request_repaint();
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading metadata...");
            });
            return;
        }

        if let Some(ref err) = state.error {
            ui.label(
                egui::RichText::new(err).color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
            );
            return;
        }

        let label_color = egui::Color32::from_rgb(0x66, 0x66, 0x66);
        let value_color = egui::Color32::from_rgb(0xCC, 0xCC, 0xCC);

        if state.entries.is_empty() {
            ui.label(
                egui::RichText::new("No metadata detected for this file type.")
                    .size(11.0)
                    .color(label_color),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Supported: PDF, DOCX/XLSX/PPTX, JPEG, PNG")
                    .size(10.0)
                    .color(egui::Color32::from_rgb(0x44, 0x44, 0x44)),
            );
            return;
        }

        ui.label(
            egui::RichText::new(&state.format_name)
                .strong()
                .size(11.0)
                .color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
        );
        ui.add_space(2.0);

        egui::Grid::new("metadata_grid")
            .striped(true)
            .min_col_width(80.0)
            .show(ui, |ui| {
                for entry in &state.entries {
                    ui.label(
                        egui::RichText::new(&entry.key)
                            .size(11.0)
                            .color(label_color),
                    );
                    ui.label(
                        egui::RichText::new(&entry.value)
                            .size(11.0)
                            .color(value_color),
                    );
                    ui.end_row();
                }
            });
    }

    fn is_loading(&self) -> bool {
        !self.state.lock().unwrap().done
    }
}