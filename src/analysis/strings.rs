use super::AnalysisTab;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub encoding: StringEncoding,
    pub category: StringCategory,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StringCategory {
    Plain,
    Url,
    FilePath,
    RegistryKey,
    IpAddress,
    Email,
}

impl StringCategory {
    pub fn color(&self) -> egui::Color32 {
        match self {
            Self::Plain => egui::Color32::from_rgb(0xCC, 0xCC, 0xCC),
            Self::Url => egui::Color32::from_rgb(0x60, 0xA0, 0xFF),
            Self::FilePath => egui::Color32::from_rgb(0x80, 0xD0, 0x80),
            Self::RegistryKey => egui::Color32::from_rgb(0xE0, 0xA0, 0x40),
            Self::IpAddress => egui::Color32::from_rgb(0xD0, 0x70, 0xD0),
            Self::Email => egui::Color32::from_rgb(0x50, 0xD0, 0xD0),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Plain => "TXT",
            Self::Url => "URL",
            Self::FilePath => "PATH",
            Self::RegistryKey => "REG",
            Self::IpAddress => "IP",
            Self::Email => "EMAIL",
        }
    }

    pub fn all() -> &'static [StringCategory] {
        &[
            Self::Plain,
            Self::Url,
            Self::FilePath,
            Self::RegistryKey,
            Self::IpAddress,
            Self::Email,
        ]
    }
}

fn categorize_string(s: &str) -> StringCategory {
    let lower = s.to_lowercase();

    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
    {
        return StringCategory::Url;
    }

    if s.contains('@') && s.contains('.') && !s.contains(' ') && s.len() > 5 {
        let parts: Vec<&str> = s.split('@').collect();
        if parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.') {
            return StringCategory::Email;
        }
    }

    if lower.starts_with("hkey_")
        || lower.starts_with("hklm\\")
        || lower.starts_with("hkcu\\")
        || lower.starts_with("software\\")
    {
        return StringCategory::RegistryKey;
    }

    if s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.matches('.').count() == 3 {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| p.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
        {
            return StringCategory::IpAddress;
        }
    }

    if (s.contains('\\') && (s.contains(":\\") || s.starts_with("\\\\")))
        || (s.starts_with('/') && s.len() > 2)
        || lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.ends_with(".inf")
    {
        return StringCategory::FilePath;
    }

    StringCategory::Plain
}

fn extract_ascii_strings(
    data: &[u8],
    min_len: usize,
    cancel: &AtomicBool,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i & 0xFFFF == 0 && cancel.load(Ordering::Relaxed) {
            return results;
        }

        if byte >= 0x20 && byte < 0x7F {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                let s: String = current.iter().collect();
                let category = categorize_string(&s);
                results.push(ExtractedString {
                    value: s,
                    offset: start_offset,
                    encoding: StringEncoding::Ascii,
                    category,
                });
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        let s: String = current.iter().collect();
        let category = categorize_string(&s);
        results.push(ExtractedString {
            value: s,
            offset: start_offset,
            encoding: StringEncoding::Ascii,
            category,
        });
    }

    results
}

fn extract_utf16le_strings(
    data: &[u8],
    min_len: usize,
    cancel: &AtomicBool,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        if i & 0xFFFF == 0 && cancel.load(Ordering::Relaxed) {
            return results;
        }

        let ch = u16::from_le_bytes([data[i], data[i + 1]]);

        if ch >= 0x20 && ch < 0x7F {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(ch as u8 as char);
        } else {
            if current.len() >= min_len {
                let s: String = current.iter().collect();
                let category = categorize_string(&s);
                results.push(ExtractedString {
                    value: s,
                    offset: start_offset,
                    encoding: StringEncoding::Utf16Le,
                    category,
                });
            }
            current.clear();
        }

        i += 2;
    }

    if current.len() >= min_len {
        let s: String = current.iter().collect();
        let category = categorize_string(&s);
        results.push(ExtractedString {
            value: s,
            offset: start_offset,
            encoding: StringEncoding::Utf16Le,
            category,
        });
    }

    results
}

#[derive(Clone, Debug)]
pub struct StringsState {
    pub all_strings: Vec<ExtractedString>,
    pub error: Option<String>,
    pub done: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum SortMode {
    Offset,
    Length,
    Category,
    Alpha,
}

pub struct StringsTab {
    state: Arc<Mutex<StringsState>>,
    min_length: usize,
    search_text: String,
    started: bool,
    copy_states: std::collections::HashMap<usize, std::time::Instant>,
    category_filters: std::collections::HashSet<StringCategory>,
    dedup: bool,
    sort_mode: SortMode,
    cancel: Arc<AtomicBool>,
}

impl StringsTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(StringsState {
                all_strings: Vec::new(),
                error: None,
                done: false,
            })),
            min_length: 4,
            search_text: String::new(),
            started: false,
            copy_states: std::collections::HashMap::new(),
            category_filters: StringCategory::all().iter().copied().collect(),
            dedup: false,
            sort_mode: SortMode::Offset,
            cancel,
        }
    }
}

impl AnalysisTab for StringsTab {
    fn name(&self) -> &str {
        "Strings"
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
            match std::fs::read(&path) {
                Ok(data) => {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }

                    let mut strings = extract_ascii_strings(&data, 3, &cancel);
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }

                    let utf16 = extract_utf16le_strings(&data, 3, &cancel);
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }

                    let ascii_set: std::collections::HashSet<String> =
                        strings.iter().map(|s| s.value.clone()).collect();
                    for s in utf16 {
                        if !ascii_set.contains(&s.value) {
                            strings.push(s);
                        }
                    }

                    strings.sort_by_key(|s| s.offset);

                    let mut st = state.lock().unwrap();
                    st.all_strings = strings;
                    st.done = true;
                }
                Err(e) => {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut st = state.lock().unwrap();
                    st.error = Some(format!("Cannot read file: {e}"));
                    st.done = true;
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
                ui.label("Extracting strings...");
            });
            return;
        }

        if let Some(ref err) = state.error {
            ui.label(
                egui::RichText::new(err).color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
            );
            return;
        }

        let max_len = state
            .all_strings
            .iter()
            .map(|s| s.value.len())
            .max()
            .unwrap_or(16)
            .max(16);

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Min:").size(10.0));
            ui.add(egui::Slider::new(&mut self.min_length, 3..=max_len).text(""));
            ui.separator();

            let dedup_text = if self.dedup { "Dedup: ON" } else { "Dedup: off" };
            let dedup_color = if self.dedup {
                egui::Color32::from_rgb(0xCC, 0x22, 0x22)
            } else {
                egui::Color32::from_rgb(0x66, 0x66, 0x66)
            };
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new(dedup_text).size(10.0).color(dedup_color),
                    )
                    .frame(true),
                )
                .clicked()
            {
                self.dedup = !self.dedup;
            }
        });

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("\u{1F50D}").size(10.0));
            ui.add_sized(
                [ui.available_width() - 120.0, 18.0],
                egui::TextEdit::singleline(&mut self.search_text),
            );
            ui.separator();

            let sort_options = [
                (SortMode::Offset, "Ofs"),
                (SortMode::Length, "Len"),
                (SortMode::Category, "Cat"),
                (SortMode::Alpha, "A-Z"),
            ];
            for (mode, label) in &sort_options {
                let is_active = self.sort_mode == *mode;
                let color = if is_active {
                    egui::Color32::from_rgb(0xCC, 0x22, 0x22)
                } else {
                    egui::Color32::from_rgb(0x66, 0x66, 0x66)
                };
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new(*label).size(9.0).color(color),
                        )
                        .frame(is_active),
                    )
                    .clicked()
                {
                    self.sort_mode = *mode;
                }
            }
        });

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            for cat in StringCategory::all() {
                let enabled = self.category_filters.contains(cat);
                let color = if enabled {
                    cat.color()
                } else {
                    egui::Color32::from_rgb(0x33, 0x33, 0x33)
                };
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new(cat.label()).size(9.0).color(color),
                        )
                        .frame(enabled),
                    )
                    .clicked()
                {
                    if enabled {
                        self.category_filters.remove(cat);
                    } else {
                        self.category_filters.insert(*cat);
                    }
                }
            }
        });

        let search_lower = self.search_text.to_lowercase();
        let mut filtered: Vec<&ExtractedString> = state
            .all_strings
            .iter()
            .filter(|s| s.value.len() >= self.min_length)
            .filter(|s| self.category_filters.contains(&s.category))
            .filter(|s| {
                search_lower.is_empty() || s.value.to_lowercase().contains(&search_lower)
            })
            .collect();

        match self.sort_mode {
            SortMode::Offset => filtered.sort_by_key(|s| s.offset),
            SortMode::Length => filtered.sort_by(|a, b| b.value.len().cmp(&a.value.len())),
            SortMode::Category => {
                filtered.sort_by_key(|s| format!("{:?}", s.category));
            }
            SortMode::Alpha => {
                filtered.sort_by(|a, b| a.value.to_lowercase().cmp(&b.value.to_lowercase()));
            }
        }

        let (display_strings, dedup_counts): (Vec<&ExtractedString>, Vec<usize>) = if self.dedup {
            let mut seen = std::collections::HashMap::<&str, (usize, usize)>::new();
            let mut indices = Vec::new();

            for (i, s) in filtered.iter().enumerate() {
                let entry = seen.entry(&s.value).or_insert((i, 0));
                entry.1 += 1;
                if entry.1 == 1 {
                    indices.push(i);
                }
            }

            let strs: Vec<&ExtractedString> = indices.iter().map(|&i| filtered[i]).collect();
            let counts: Vec<usize> = strs
                .iter()
                .map(|s| seen[s.value.as_str()].1)
                .collect();
            (strs, counts)
        } else {
            let len = filtered.len();
            (filtered, vec![1; len])
        };

        let total_count = state
            .all_strings
            .iter()
            .filter(|s| s.value.len() >= self.min_length)
            .count();

        ui.label(
            egui::RichText::new(format!("{} / {total_count}", display_strings.len()))
                .size(10.0)
                .color(egui::Color32::from_rgb(0x55, 0x55, 0x55)),
        );

        ui.separator();

        self.copy_states
            .retain(|_, t| t.elapsed().as_millis() < 1500);
        let mut any_copied = !self.copy_states.is_empty();

        let row_height = 18.0;

        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, display_strings.len(), |ui, row_range| {
                for row_idx in row_range {
                    if let Some(&s) = display_strings.get(row_idx) {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 3.0;

                            ui.label(
                                egui::RichText::new(format!("[{}]", s.category.label()))
                                    .size(9.0)
                                    .color(s.category.color()),
                            );

                            let enc_label = match s.encoding {
                                StringEncoding::Ascii => "A",
                                StringEncoding::Utf16Le => "U",
                            };
                            ui.label(
                                egui::RichText::new(enc_label)
                                    .size(9.0)
                                    .color(egui::Color32::from_rgb(0x44, 0x44, 0x44)),
                            );

                            let offset_text = format!("{:08X}", s.offset);
                            let offset_resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&offset_text)
                                        .monospace()
                                        .size(10.0)
                                        .color(egui::Color32::from_rgb(0x55, 0x55, 0x55)),
                                )
                                .sense(egui::Sense::click()),
                            );
                            if offset_resp.clicked() {
                                ui.ctx().copy_text(offset_text);
                            }
                            offset_resp.on_hover_text("Copy offset");

                            if self.dedup {
                                if let Some(&count) = dedup_counts.get(row_idx) {
                                    if count > 1 {
                                        ui.label(
                                            egui::RichText::new(format!("x{count}"))
                                                .size(9.0)
                                                .color(egui::Color32::from_rgb(
                                                    0xCC, 0x22, 0x22,
                                                )),
                                        );
                                    }
                                }
                            }

                            let display_val = if s.value.len() > 120 {
                                format!("{}...", &s.value[..120])
                            } else {
                                s.value.clone()
                            };
                            ui.label(
                                egui::RichText::new(&display_val)
                                    .monospace()
                                    .size(10.5)
                                    .color(s.category.color()),
                            );

                            let is_copied = self
                                .copy_states
                                .get(&row_idx)
                                .map(|t| t.elapsed().as_millis() < 1500)
                                .unwrap_or(false);

                            let btn_text = if is_copied { "\u{2713}" } else { "\u{1F4CB}" };
                            if ui.small_button(btn_text).clicked() {
                                ui.ctx().copy_text(s.value.clone());
                                self.copy_states
                                    .insert(row_idx, std::time::Instant::now());
                                any_copied = true;
                            }
                        });
                    }
                }
            });

        if any_copied {
            ctx.request_repaint();
        }
    }

    fn is_loading(&self) -> bool {
        !self.state.lock().unwrap().done
    }
}