use super::AnalysisTab;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug)]
pub struct HashResult {
    pub algorithm: String,
    pub digest: Option<String>,
    pub error: Option<String>,
    pub computing: bool,
}

#[derive(Clone, Debug)]
struct CopyState {
    copied_at: Option<std::time::Instant>,
}

pub struct HashesTab {
    results: Arc<Mutex<Vec<HashResult>>>,
    copy_states: Vec<CopyState>,
    started: bool,
    cancel: Arc<AtomicBool>,
}

impl HashesTab {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        let initial = vec![
            HashResult {
                algorithm: "MD5".into(),
                digest: None,
                error: None,
                computing: false,
            },
            HashResult {
                algorithm: "SHA-1".into(),
                digest: None,
                error: None,
                computing: false,
            },
            HashResult {
                algorithm: "SHA-256".into(),
                digest: None,
                error: None,
                computing: false,
            },
        ];
        Self {
            results: Arc::new(Mutex::new(initial)),
            copy_states: vec![CopyState { copied_at: None }; 3],
            started: false,
            cancel,
        }
    }
}

fn compute_hash(path: &Path, algo: &str, cancel: &AtomicBool) -> Result<String, String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open: {e}"))?;
    let mut buffer = [0u8; 8192];

    macro_rules! hash_loop {
        ($hasher:expr) => {{
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled".into());
                }
                let bytes_read = file
                    .read(&mut buffer)
                    .map_err(|e| format!("Read error: {e}"))?;
                if bytes_read == 0 {
                    break;
                }
                $hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", $hasher.finalize()))
        }};
    }

    match algo {
        "MD5" => {
            use md5::Digest;
            let mut hasher = md5::Md5::new();
            hash_loop!(hasher)
        }
        "SHA-1" => {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::new();
            hash_loop!(hasher)
        }
        "SHA-256" => {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hash_loop!(hasher)
        }
        _ => Err(format!("Unknown algorithm: {algo}")),
    }
}

impl AnalysisTab for HashesTab {
    fn name(&self) -> &str {
        "Hashes"
    }

    fn run(&mut self, path: &Path) {
        if self.started {
            return;
        }
        self.started = true;

        let results = self.results.clone();
        {
            let mut r = results.lock().unwrap();
            for item in r.iter_mut() {
                item.computing = true;
            }
        }

        let algos = ["MD5", "SHA-1", "SHA-256"];
        for (i, algo) in algos.iter().enumerate() {
            let path = path.to_path_buf();
            let results = results.clone();
            let algo = algo.to_string();
            let cancel = self.cancel.clone();

            thread::spawn(move || {
                let result = compute_hash(&path, &algo, &cancel);

                if cancel.load(Ordering::Relaxed) {
                    return;
                }

                let mut r = results.lock().unwrap();
                r[i].computing = false;
                match result {
                    Ok(digest) => r[i].digest = Some(digest),
                    Err(e) => r[i].error = Some(e),
                }
            });
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let results = self.results.lock().unwrap().clone();
        let any_computing = results.iter().any(|r| r.computing);

        if any_computing {
            ctx.request_repaint();
        }

        ui.add_space(4.0);

        for (i, result) in results.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("{}:", result.algorithm))
                        .strong()
                        .size(11.0),
                );

                if result.computing {
                    ui.spinner();
                    ui.label(
                        egui::RichText::new("computing...")
                            .size(10.0)
                            .color(egui::Color32::from_rgb(0x55, 0x55, 0x55))
                            .italics(),
                    );
                } else if let Some(ref err) = result.error {
                    ui.label(
                        egui::RichText::new(err)
                            .size(10.0)
                            .color(egui::Color32::from_rgb(0xCC, 0x22, 0x22)),
                    );
                } else if let Some(ref digest) = result.digest {
                    while self.copy_states.len() <= i {
                        self.copy_states.push(CopyState { copied_at: None });
                    }

                    let is_copied = self.copy_states[i]
                        .copied_at
                        .map(|t| t.elapsed().as_millis() < 1500)
                        .unwrap_or(false);

                    let btn_text = if is_copied { "\u{2713}" } else { "\u{1F4CB}" };
                    if ui.small_button(btn_text).clicked() {
                        ui.ctx().copy_text(digest.clone());
                        self.copy_states[i].copied_at = Some(std::time::Instant::now());
                    }

                    if is_copied {
                        ctx.request_repaint();
                    }
                }
            });

            if let Some(ref digest) = result.digest {
                let mut text = digest.clone();
                egui::TextEdit::singleline(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .interactive(true)
                    .show(ui);
            }

            ui.add_space(3.0);
        }
    }

    fn is_loading(&self) -> bool {
        self.results.lock().unwrap().iter().any(|r| r.computing)
    }
}