use super::AnalysisTab;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_HEX_BYTES: usize = 64 * 1024;
const BYTES_PER_ROW: usize = 16;

#[derive(Clone)]
pub struct HexState {
    pub data: Vec<u8>,
    pub total_file_size: u64,
    pub error: Option<String>,
    pub done: bool,
}

pub struct HexTab {
    state: Arc<Mutex<HexState>>,
    started: bool,
    selected_offset: Option<usize>,
    cancel: Arc<AtomicBool>,
}

impl HexTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(HexState {
                data: Vec::new(),
                total_file_size: 0,
                error: None,
                done: false,
            })),
            started: false,
            selected_offset: None,
            cancel,
        }
    }
}

impl AnalysisTab for HexTab {
    fn name(&self) -> &str {
        "Hex"
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
                    let total = data.len() as u64;
                    let truncated = if data.len() > MAX_HEX_BYTES {
                        data[..MAX_HEX_BYTES].to_vec()
                    } else {
                        data
                    };
                    let mut s = state.lock().unwrap();
                    s.data = truncated;
                    s.total_file_size = total;
                    s.done = true;
                }
                Err(e) => {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut s = state.lock().unwrap();
                    s.error = Some(format!("Read error: {e}"));
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
                ui.label("Loading...");
            });
            return;
        }

        if let Some(ref err) = state.error {
            ui.label(
                egui::RichText::new(err).color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
            );
            return;
        }

        let dim_color = egui::Color32::from_rgb(0x55, 0x55, 0x55);
        let byte_color = egui::Color32::from_rgb(0xAA, 0xAA, 0xAA);
        let selected_color = egui::Color32::from_rgb(0xCC, 0x22, 0x22);
        let ascii_color = egui::Color32::from_rgb(0x80, 0xD0, 0x80);
        let zero_color = egui::Color32::from_rgb(0x33, 0x33, 0x33);

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "Showing {} / {} bytes",
                    state.data.len(),
                    state.total_file_size
                ))
                .size(10.0)
                .color(dim_color),
            );

            if let Some(offset) = self.selected_offset {
                if offset < state.data.len() {
                    let byte = state.data[offset];
                    let ch = if byte >= 0x20 && byte < 0x7F {
                        byte as char
                    } else {
                        '.'
                    };
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "Offset: 0x{offset:08X}  Dec: {byte}  Hex: 0x{byte:02X}  Char: '{ch}'"
                        ))
                        .monospace()
                        .size(10.0)
                        .color(selected_color),
                    );
                }
            }
        });

        ui.separator();

        let num_rows = (state.data.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW;
        let row_height = 15.0;

        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, num_rows, |ui, row_range| {
                for row in row_range {
                    let base_offset = row * BYTES_PER_ROW;

                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;

                        ui.label(
                            egui::RichText::new(format!("{base_offset:08X}  "))
                                .monospace()
                                .size(10.0)
                                .color(dim_color),
                        );

                        for col in 0..BYTES_PER_ROW {
                            let idx = base_offset + col;

                            if idx < state.data.len() {
                                let byte = state.data[idx];
                                let is_selected = self.selected_offset == Some(idx);

                                let color = if is_selected {
                                    selected_color
                                } else if byte == 0 {
                                    zero_color
                                } else {
                                    byte_color
                                };

                                let resp = ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(format!("{byte:02X}"))
                                            .monospace()
                                            .size(10.0)
                                            .color(color),
                                    )
                                    .sense(egui::Sense::click()),
                                );

                                if resp.clicked() {
                                    self.selected_offset = Some(idx);
                                }
                            } else {
                                ui.label(
                                    egui::RichText::new("  ").monospace().size(10.0),
                                );
                            }

                            let spacer = if col == 7 { "  " } else { " " };
                            ui.label(
                                egui::RichText::new(spacer).monospace().size(10.0),
                            );
                        }

                        ui.label(egui::RichText::new(" ").monospace().size(10.0));

                        let mut ascii = String::with_capacity(BYTES_PER_ROW);
                        for col in 0..BYTES_PER_ROW {
                            let idx = base_offset + col;
                            if idx < state.data.len() {
                                let byte = state.data[idx];
                                ascii.push(if byte >= 0x20 && byte < 0x7F {
                                    byte as char
                                } else {
                                    '.'
                                });
                            }
                        }
                        ui.label(
                            egui::RichText::new(ascii)
                                .monospace()
                                .size(10.0)
                                .color(ascii_color),
                        );
                    });
                }
            });
    }

    fn is_loading(&self) -> bool {
        !self.state.lock().unwrap().done
    }
}