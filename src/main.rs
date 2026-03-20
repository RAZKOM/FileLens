#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod analysis;
mod config;
mod registry;
mod ui;

use config::AppConfig;
use std::path::PathBuf;
use ui::FileLensApp;

fn get_cursor_position() -> (f32, f32) {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
        use windows::Win32::Foundation::POINT;

        let mut point = POINT { x: 0, y: 0 };
        unsafe {
            let _ = GetCursorPos(&mut point);
        }
        (point.x as f32, point.y as f32)
    }

    #[cfg(not(target_os = "windows"))]
    {
        (400.0, 300.0)
    }
}

fn get_screen_size() -> (f32, f32) {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN) as f32;
            let h = GetSystemMetrics(SM_CYSCREEN) as f32;
            (w, h)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        (1920.0, 1080.0)
    }
}

fn nudge_position(x: f32, y: f32, win_w: f32, win_h: f32, screen_w: f32, screen_h: f32) -> (f32, f32) {
    let margin = 10.0;
    let mut nx = x;
    let mut ny = y;

    if nx + win_w > screen_w - margin {
        nx = screen_w - win_w - margin;
    }
    if ny + win_h > screen_h - margin {
        ny = screen_h - win_h - margin;
    }
    if nx < margin {
        nx = margin;
    }
    if ny < margin {
        ny = margin;
    }

    (nx, ny)
}

fn load_icon() -> Option<egui::IconData> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidates = [
        exe_dir.join("filelens.png"),
        exe_dir.join("assets").join("filelens.png"),
        exe_dir.join("icon.png"),
        exe_dir.join("assets").join("icon.png"),
    ];

    for path in &candidates {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(img) = image::load_from_memory(&data) {
                let rgba = img.to_rgba8();
                let (w, h) = rgba.dimensions();
                return Some(egui::IconData {
                    rgba: rgba.into_raw(),
                    width: w,
                    height: h,
                });
            }
        }
    }

    None
}

fn print_usage() {
    eprintln!("FileLens - Right-click file inspector");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  filelens <file_path>    Inspect a file");
    eprintln!("  filelens --register     Register context menu");
    eprintln!("  filelens --unregister   Remove context menu");
    eprintln!("  filelens --help         Show this help");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        eprintln!();
        eprintln!("No file specified. Attempting to register context menu...");
        match registry::win32::register_context_menu() {
            Ok(()) => eprintln!("Context menu registered successfully."),
            Err(e) => eprintln!("Failed to register: {e}"),
        }
        return Ok(());
    }

    let arg = &args[1];

    match arg.as_str() {
        "--register" => {
            match registry::win32::register_context_menu() {
                Ok(()) => {
                    eprintln!("Context menu registered successfully.");
                    eprintln!("Right-click any file in Explorer to see 'Inspect with FileLens'.");
                }
                Err(e) => eprintln!("Failed to register: {e}"),
            }
            return Ok(());
        }
        "--unregister" => {
            match registry::win32::unregister_context_menu() {
                Ok(()) => eprintln!("Context menu unregistered successfully."),
                Err(e) => eprintln!("Failed to unregister: {e}"),
            }
            return Ok(());
        }
        "--help" | "-h" => {
            print_usage();
            return Ok(());
        }
        _ => {}
    }

    let file_path = PathBuf::from(arg);
    if !file_path.exists() {
        eprintln!("Error: file not found: {}", file_path.display());
        return Ok(());
    }

    let config = AppConfig::load();
    let win_w = config.window_width;
    let win_h = config.window_height;

    let (cx, cy) = get_cursor_position();
    let (sw, sh) = get_screen_size();
    let (px, py) = nudge_position(cx, cy, win_w, win_h, sw, sh);

    let icon_data = load_icon();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([win_w, win_h])
        .with_position([px, py])
        .with_decorations(false)
        .with_always_on_top()
        .with_taskbar(false)
        .with_resizable(false) // we handle resize ourselves for borderless
        .with_min_inner_size([400.0, 200.0])
        .with_transparent(false);

    if let Some(icon) = icon_data {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "FileLens",
        native_options,
        Box::new(move |cc| {
            cc.egui_ctx.set_fonts(egui::FontDefinitions::default());

            Ok(Box::new(FileLensApp::new(file_path.clone(), config.clone())))
        }),
    )
    .map_err(|e| format!("eframe error: {e}"))?;

    Ok(())
}