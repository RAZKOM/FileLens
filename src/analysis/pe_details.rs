use super::AnalysisTab;
use super::info::{compute_entropy, read_u16_le, read_u32_le, rva_to_offset};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_addr: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    pub entropy: f64,
}

#[derive(Clone, Debug)]
pub struct ImportDll {
    pub name: String,
    pub functions: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeDetails {
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportDll>,
    pub exports: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeDetailsState {
    pub details: Option<PeDetails>,
    pub error: Option<String>,
    pub not_pe: bool,
    pub done: bool,
}

pub struct PeDetailsTab {
    state: Arc<Mutex<PeDetailsState>>,
    started: bool,
    cancel: Arc<AtomicBool>,
}

impl PeDetailsTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(PeDetailsState {
                details: None,
                error: None,
                not_pe: false,
                done: false,
            })),
            started: false,
            cancel,
        }
    }
}

fn section_flags_str(chars: u32) -> String {
    let mut flags = Vec::new();
    if chars & 0x00000020 != 0 {
        flags.push("CODE");
    }
    if chars & 0x00000040 != 0 {
        flags.push("IDATA");
    }
    if chars & 0x00000080 != 0 {
        flags.push("UDATA");
    }
    if chars & 0x20000000 != 0 {
        flags.push("X");
    }
    if chars & 0x40000000 != 0 {
        flags.push("R");
    }
    if chars & 0x80000000 != 0 {
        flags.push("W");
    }
    if flags.is_empty() {
        "---".into()
    } else {
        flags.join("|")
    }
}

fn read_string_at(data: &[u8], offset: usize, max_len: usize) -> String {
    let mut s = String::new();
    for i in 0..max_len {
        if offset + i >= data.len() {
            break;
        }
        let b = data[offset + i];
        if b == 0 {
            break;
        }
        if b >= 0x20 && b < 0x7F {
            s.push(b as char);
        } else {
            break;
        }
    }
    s
}

fn analyze_pe(path: &Path, cancel: &AtomicBool) -> Result<Option<PeDetails>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read error: {e}"))?;

    if cancel.load(Ordering::Relaxed) {
        return Err("Cancelled".into());
    }

    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return Ok(None);
    }
    let pe_offset = read_u32_le(&data, 0x3C) as usize;
    if pe_offset + 24 > data.len() {
        return Ok(None);
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(None);
    }

    let coff_offset = pe_offset + 4;
    let num_sections = read_u16_le(&data, coff_offset + 2);
    let opt_hdr_size = read_u16_le(&data, coff_offset + 16) as usize;
    let section_table_offset = coff_offset + 20 + opt_hdr_size;

    let mut sections = Vec::new();
    for i in 0..num_sections as usize {
        let off = section_table_offset + i * 40;
        if off + 40 > data.len() {
            break;
        }

        let name = read_string_at(&data, off, 8);
        let virtual_size = read_u32_le(&data, off + 8);
        let virtual_addr = read_u32_le(&data, off + 12);
        let raw_size = read_u32_le(&data, off + 16);
        let raw_offset = read_u32_le(&data, off + 20);
        let characteristics = read_u32_le(&data, off + 36);

        let entropy = if raw_size > 0
            && (raw_offset as usize + raw_size as usize) <= data.len()
        {
            compute_entropy(&data[raw_offset as usize..(raw_offset + raw_size) as usize])
        } else {
            0.0
        };

        sections.push(SectionInfo {
            name,
            virtual_addr,
            virtual_size,
            raw_size,
            raw_offset,
            characteristics,
            entropy,
        });
    }

    let opt_offset = coff_offset + 20;
    let opt_magic = read_u16_le(&data, opt_offset);

    let (num_data_dirs_offset, data_dir_start) = match opt_magic {
        0x10B => (opt_offset + 92, opt_offset + 96),
        0x20B => (opt_offset + 108, opt_offset + 112),
        _ => (0, 0),
    };

    let mut imports = Vec::new();
    let mut exports = Vec::new();

    if data_dir_start > 0 && num_data_dirs_offset + 4 <= data.len() {
        let num_data_dirs = read_u32_le(&data, num_data_dirs_offset) as usize;

        if num_data_dirs > 1 && data_dir_start + 16 <= data.len() {
            let import_rva = read_u32_le(&data, data_dir_start + 8);

            if import_rva > 0 {
                if let Some(import_offset) =
                    rva_to_offset(&data, pe_offset, num_sections, import_rva)
                {
                    let mut pos = import_offset;
                    while pos + 20 <= data.len() {
                        let name_rva = read_u32_le(&data, pos + 12);
                        if name_rva == 0 {
                            break;
                        }

                        let dll_name = rva_to_offset(&data, pe_offset, num_sections, name_rva)
                            .map(|off| read_string_at(&data, off, 256))
                            .unwrap_or_else(|| format!("RVA:0x{name_rva:08X}"));

                        let mut functions = Vec::new();
                        let ilt_rva = read_u32_le(&data, pos); // OriginalFirstThunk
                        let ilt_rva = if ilt_rva != 0 {
                            ilt_rva
                        } else {
                            read_u32_le(&data, pos + 16) // FirstThunk fallback
                        };

                        if ilt_rva != 0 {
                            if let Some(ilt_offset) =
                                rva_to_offset(&data, pe_offset, num_sections, ilt_rva)
                            {
                                let entry_size: usize =
                                    if opt_magic == 0x20B { 8 } else { 4 };
                                let mut entry_pos = ilt_offset;
                                let mut count = 0;

                                while entry_pos + entry_size <= data.len() && count < 500 {
                                    let entry = if entry_size == 8 {
                                        let lo =
                                            read_u32_le(&data, entry_pos) as u64;
                                        let hi =
                                            read_u32_le(&data, entry_pos + 4) as u64;
                                        hi << 32 | lo
                                    } else {
                                        read_u32_le(&data, entry_pos) as u64
                                    };

                                    if entry == 0 {
                                        break;
                                    }

                                    let is_ordinal = if entry_size == 8 {
                                        entry & (1u64 << 63) != 0
                                    } else {
                                        entry & (1u64 << 31) != 0
                                    };

                                    if is_ordinal {
                                        functions.push(format!(
                                            "Ordinal #{}",
                                            entry & 0xFFFF
                                        ));
                                    } else {
                                        let hint_rva = (entry & 0x7FFFFFFF) as u32;
                                        if let Some(hint_offset) = rva_to_offset(
                                            &data,
                                            pe_offset,
                                            num_sections,
                                            hint_rva,
                                        ) {
                                            let fname = read_string_at(
                                                &data,
                                                hint_offset + 2,
                                                256,
                                            );
                                            if !fname.is_empty() {
                                                functions.push(fname);
                                            } else {
                                                functions.push(format!(
                                                    "0x{hint_rva:08X}"
                                                ));
                                            }
                                        }
                                    }

                                    entry_pos += entry_size;
                                    count += 1;
                                }
                            }
                        }

                        imports.push(ImportDll {
                            name: dll_name,
                            functions,
                        });
                        pos += 20;
                    }
                }
            }
        }

        if num_data_dirs > 0 && data_dir_start + 8 <= data.len() {
            let export_rva = read_u32_le(&data, data_dir_start);
            let export_size = read_u32_le(&data, data_dir_start + 4);

            if export_rva > 0 && export_size > 0 {
                if let Some(exp_offset) =
                    rva_to_offset(&data, pe_offset, num_sections, export_rva)
                {
                    if exp_offset + 40 <= data.len() {
                        let num_names = read_u32_le(&data, exp_offset + 24) as usize;
                        let names_rva = read_u32_le(&data, exp_offset + 32);

                        if let Some(names_offset) =
                            rva_to_offset(&data, pe_offset, num_sections, names_rva)
                        {
                            for i in 0..num_names.min(1000) {
                                if names_offset + i * 4 + 4 > data.len() {
                                    break;
                                }
                                let name_rva =
                                    read_u32_le(&data, names_offset + i * 4);
                                if let Some(n_offset) = rva_to_offset(
                                    &data,
                                    pe_offset,
                                    num_sections,
                                    name_rva,
                                ) {
                                    exports.push(read_string_at(&data, n_offset, 256));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Some(PeDetails {
        sections,
        imports,
        exports,
    }))
}

impl AnalysisTab for PeDetailsTab {
    fn name(&self) -> &str {
        "PE"
    }

    fn relevant_for(&self, path: &std::path::Path) -> bool {
        super::is_pe_file(path)
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
            match analyze_pe(&path, &cancel) {
                Ok(Some(details)) => {
                    let mut s = state.lock().unwrap();
                    s.details = Some(details);
                    s.done = true;
                }
                Ok(None) => {
                    let mut s = state.lock().unwrap();
                    s.not_pe = true;
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
                ui.label("Parsing PE...");
            });
            return;
        }

        if state.not_pe {
            ui.label(
                egui::RichText::new("Not a PE file")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(0x66, 0x66, 0x66)),
            );
            return;
        }

        if let Some(ref err) = state.error {
            ui.label(
                egui::RichText::new(err).color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
            );
            return;
        }

        let details = match &state.details {
            Some(d) => d,
            None => return,
        };

        let label_color = egui::Color32::from_rgb(0x66, 0x66, 0x66);
        let value_color = egui::Color32::from_rgb(0xCC, 0xCC, 0xCC);
        let warn_color = egui::Color32::from_rgb(0xCC, 0x22, 0x22);

        ui.label(
            egui::RichText::new("Sections")
                .strong()
                .size(11.0)
                .color(warn_color),
        );

        egui::Grid::new("sections_grid")
            .striped(true)
            .min_col_width(40.0)
            .show(ui, |ui| {
                for header in &["Name", "VAddr", "VSize", "RawSz", "Entropy", "Flags"] {
                    ui.label(
                        egui::RichText::new(*header)
                            .size(10.0)
                            .color(label_color),
                    );
                }
                ui.end_row();

                for sec in &details.sections {
                    ui.label(
                        egui::RichText::new(&sec.name)
                            .monospace()
                            .size(10.0)
                            .color(value_color),
                    );
                    ui.label(
                        egui::RichText::new(format!("{:08X}", sec.virtual_addr))
                            .monospace()
                            .size(10.0)
                            .color(value_color),
                    );
                    ui.label(
                        egui::RichText::new(format!("{:X}", sec.virtual_size))
                            .monospace()
                            .size(10.0)
                            .color(value_color),
                    );
                    ui.label(
                        egui::RichText::new(format!("{:X}", sec.raw_size))
                            .monospace()
                            .size(10.0)
                            .color(value_color),
                    );

                    let entropy_color = if sec.entropy > 7.5 {
                        warn_color
                    } else if sec.entropy > 6.5 {
                        egui::Color32::from_rgb(0xE0, 0xA0, 0x40)
                    } else {
                        value_color
                    };
                    ui.label(
                        egui::RichText::new(format!("{:.2}", sec.entropy))
                            .monospace()
                            .size(10.0)
                            .color(entropy_color),
                    );

                    ui.label(
                        egui::RichText::new(section_flags_str(sec.characteristics))
                            .monospace()
                            .size(9.0)
                            .color(label_color),
                    );
                    ui.end_row();
                }
            });

        ui.add_space(4.0);
        ui.separator();

        ui.label(
            egui::RichText::new(format!("Imports ({} DLLs)", details.imports.len()))
                .strong()
                .size(11.0)
                .color(warn_color),
        );

        egui::ScrollArea::both()
            .id_salt("imports_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for dll in &details.imports {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(&dll.name)
                                .strong()
                                .size(10.0)
                                .color(egui::Color32::from_rgb(0x60, 0xA0, 0xFF)),
                        );
                        ui.label(
                            egui::RichText::new(format!("({})", dll.functions.len()))
                                .size(9.0)
                                .color(label_color),
                        );
                    });

                    for func in &dll.functions {
                        ui.horizontal(|ui| {
                            ui.add_space(12.0);
                            ui.label(
                                egui::RichText::new(func)
                                    .monospace()
                                    .size(9.5)
                                    .color(value_color),
                            );
                        });
                    }
                }
            });

        if !details.exports.is_empty() {
            ui.add_space(4.0);
            ui.separator();

            ui.label(
                egui::RichText::new(format!("Exports ({})", details.exports.len()))
                    .strong()
                    .size(11.0)
                    .color(warn_color),
            );

            egui::ScrollArea::both()
                .id_salt("exports_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for exp in &details.exports {
                        ui.label(
                            egui::RichText::new(exp)
                                .monospace()
                                .size(9.5)
                                .color(value_color),
                        );
                    }
                });
        }
    }

    fn is_loading(&self) -> bool {
        !self.state.lock().unwrap().done
    }
}