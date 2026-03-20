use crate::analysis::AnalysisTab;
use crate::config::AppConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Theme;

impl Theme {
    pub const BG: egui::Color32 = egui::Color32::from_rgb(0x0E, 0x0E, 0x0E);
    pub const PANEL: egui::Color32 = egui::Color32::from_rgb(0x16, 0x16, 0x16);
    pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0xCC, 0x22, 0x22);
    pub const TEXT: egui::Color32 = egui::Color32::from_rgb(0xCC, 0xCC, 0xCC);
    pub const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(0x66, 0x66, 0x66);
    pub const BORDER: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x2A, 0x2A);
    pub const TAB_HOVER: egui::Color32 = egui::Color32::from_rgb(0x1E, 0x1E, 0x1E);
    pub const TAB_ACTIVE: egui::Color32 = egui::Color32::from_rgb(0x22, 0x22, 0x22);
}

pub struct FileLensApp {
    pub file_name: String,
    pub tabs: Vec<Box<dyn AnalysisTab>>,
    pub active_tab: usize,
    pub config: AppConfig,
    pub should_close: bool,
    pub had_focus_last_frame: bool,
    pub first_frame: bool,
    pub pinned: bool, 
    pub cancel: Arc<AtomicBool>,
    pub dragging: bool,
    pub drag_start_cursor: [f32; 2],
    pub drag_start_window: [f32; 2],
    pub resizing: bool,
    pub resize_edge: ResizeEdge,
    pub resize_start_cursor: [f32; 2],
    pub resize_start_rect: [f32; 4], // x, y, w, h
}

#[derive(Clone, Copy, PartialEq)]
pub enum ResizeEdge {
    None,
    Bottom,
    Right,
    BottomRight,
}

impl FileLensApp {
    pub fn new(file_path: PathBuf, config: AppConfig) -> Self {
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        let cancel = Arc::new(AtomicBool::new(false));
        let mut tabs = crate::analysis::create_tabs_for(&file_path, cancel.clone());
        crate::analysis::run_all(&mut tabs, &file_path);

        let active_tab = if tabs.is_empty() {
            0
        } else {
            config.last_tab.min(tabs.len() - 1)
        };

        Self {
            file_name,
            tabs,
            active_tab,
            config,
            should_close: false,
            had_focus_last_frame: true,
            first_frame: true,
            pinned: false,
            cancel,
            dragging: false,
            drag_start_cursor: [0.0; 2],
            drag_start_window: [0.0; 2],
            resizing: false,
            resize_edge: ResizeEdge::None,
            resize_start_cursor: [0.0; 2],
            resize_start_rect: [0.0; 4],
        }
    }
}

fn cursor_screen() -> [f32; 2] {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::POINT;
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
        let mut pt = POINT { x: 0, y: 0 };
        unsafe {
            let _ = GetCursorPos(&mut pt);
        }
        [pt.x as f32, pt.y as f32]
    }
    #[cfg(not(target_os = "windows"))]
    {
        [0.0, 0.0]
    }
}

pub fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = Theme::PANEL;
    visuals.window_fill = Theme::BG;
    visuals.faint_bg_color = Theme::BG;
    visuals.extreme_bg_color = egui::Color32::from_rgb(0x0A, 0x0A, 0x0A);

    visuals.widgets.noninteractive.bg_fill = Theme::PANEL;
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, Theme::TEXT);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, Theme::BORDER);

    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x1E, 0x1E, 0x1E);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, Theme::TEXT);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, Theme::BORDER);

    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x2A, 0x2A, 0x2A);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, Theme::TEXT);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, Theme::ACCENT);

    visuals.widgets.active.bg_fill = Theme::ACCENT;
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);

    visuals.selection.bg_fill = Theme::ACCENT.gamma_multiply(0.3);
    visuals.selection.stroke = egui::Stroke::new(1.0, Theme::ACCENT);

    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 2.0),
        blur: 8.0,
        spread: 0.0,
        color: egui::Color32::from_black_alpha(80),
    };
    visuals.window_stroke = egui::Stroke::new(1.0, Theme::BORDER);
    visuals.window_rounding = egui::Rounding::same(4.0);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(4.0, 2.0);
    style.spacing.window_margin = egui::Margin::same(0.0);
    style.spacing.button_padding = egui::vec2(3.0, 1.0);

    ctx.set_style(style);
}

pub fn draw_title_bar(ui: &mut egui::Ui, file_name: &str, app: &mut FileLensApp) {
    let title_bar_height = 26.0;

    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), title_bar_height),
        egui::Sense::click_and_drag(),
    );

    ui.painter().rect_filled(rect, 0.0, Theme::BG);
    ui.painter().line_segment(
        [rect.left_bottom(), rect.right_bottom()],
        egui::Stroke::new(1.0, Theme::BORDER),
    );

    let galley = ui.painter().layout_no_wrap(
        file_name.to_string(),
        egui::FontId::proportional(11.0),
        Theme::TEXT,
    );
    let text_y = rect.center().y - galley.size().y / 2.0;
    ui.painter()
        .with_clip_rect(egui::Rect::from_min_max(
            rect.min,
            egui::pos2(rect.max.x - 60.0, rect.max.y),
        ))
        .galley(egui::pos2(rect.min.x + 10.0, text_y), galley, Theme::TEXT);

    let btn_size = 20.0;
    let btn_y = rect.center().y;

    let close_rect = egui::Rect::from_center_size(
        egui::pos2(rect.max.x - 16.0, btn_y),
        egui::vec2(btn_size, btn_size),
    );
    let close_resp = ui.interact(close_rect, ui.id().with("close"), egui::Sense::click());

    let close_color = if close_resp.hovered() {
        Theme::ACCENT
    } else {
        Theme::TEXT_DIM
    };

    if close_resp.hovered() {
        ui.painter().rect_filled(
            close_rect,
            3.0,
            egui::Color32::from_rgb(0x2A, 0x14, 0x14),
        );
    }

    let margin = 5.0;
    ui.painter().line_segment(
        [
            egui::pos2(close_rect.min.x + margin, close_rect.min.y + margin),
            egui::pos2(close_rect.max.x - margin, close_rect.max.y - margin),
        ],
        egui::Stroke::new(1.5, close_color),
    );
    ui.painter().line_segment(
        [
            egui::pos2(close_rect.max.x - margin, close_rect.min.y + margin),
            egui::pos2(close_rect.min.x + margin, close_rect.max.y - margin),
        ],
        egui::Stroke::new(1.5, close_color),
    );

    if close_resp.clicked() {
        app.should_close = true;
    }

    let pin_rect = egui::Rect::from_center_size(
        egui::pos2(rect.max.x - 40.0, btn_y),
        egui::vec2(btn_size, btn_size),
    );
    let pin_resp = ui.interact(pin_rect, ui.id().with("pin"), egui::Sense::click());

    let pin_color = if app.pinned {
        Theme::ACCENT
    } else if pin_resp.hovered() {
        Theme::TEXT
    } else {
        Theme::TEXT_DIM
    };

    let sq_margin = 5.5;
    let sq_rect = egui::Rect::from_min_max(
        egui::pos2(pin_rect.min.x + sq_margin, pin_rect.min.y + sq_margin),
        egui::pos2(pin_rect.max.x - sq_margin, pin_rect.max.y - sq_margin),
    );
    if app.pinned {
        ui.painter().rect_filled(sq_rect, 1.5, pin_color);
    } else {
        ui.painter()
            .rect_stroke(sq_rect, 1.5, egui::Stroke::new(1.5, pin_color));
    }

    if pin_resp.clicked() {
        app.pinned = !app.pinned;
    }
    pin_resp.on_hover_text(if app.pinned {
        "Unpin (close on focus loss)"
    } else {
        "Pin (stay open)"
    });

    if response.drag_started() {
        app.dragging = true;
        app.drag_start_cursor = cursor_screen();
        if let Some(outer) = ui.ctx().input(|i| i.viewport().outer_rect) {
            app.drag_start_window = [outer.min.x, outer.min.y];
        }
    }

    if response.dragged() && app.dragging {
        let cursor_now = cursor_screen();
        let scale = ui
            .ctx()
            .input(|i| i.viewport().native_pixels_per_point.unwrap_or(1.0));
        let dx = (cursor_now[0] - app.drag_start_cursor[0]) / scale;
        let dy = (cursor_now[1] - app.drag_start_cursor[1]) / scale;
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(
                app.drag_start_window[0] + dx,
                app.drag_start_window[1] + dy,
            )));
    }

    if response.drag_stopped() {
        app.dragging = false;
    }
}

pub fn draw_tab_bar(ui: &mut egui::Ui, tabs: &[Box<dyn AnalysisTab>], active_tab: &mut usize) {
    let tab_height = 22.0;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

        let tab_width = ui.available_width() / tabs.len().max(1) as f32;

        for (i, tab) in tabs.iter().enumerate() {
            let is_active = i == *active_tab;

            let (rect, resp) =
                ui.allocate_exact_size(egui::vec2(tab_width, tab_height), egui::Sense::click());

            let bg = if is_active {
                Theme::TAB_ACTIVE
            } else if resp.hovered() {
                Theme::TAB_HOVER
            } else {
                Theme::BG
            };
            ui.painter().rect_filled(rect, 0.0, bg);

            if is_active {
                let indicator = egui::Rect::from_min_max(
                    egui::pos2(rect.min.x, rect.max.y - 2.0),
                    rect.max,
                );
                ui.painter().rect_filled(indicator, 0.0, Theme::ACCENT);
            }

            let text_color = if is_active {
                Theme::TEXT
            } else {
                Theme::TEXT_DIM
            };
            let mut label = tab.name().to_string();
            if tab.is_loading() {
                label.push_str("..");
            }
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                label,
                egui::FontId::proportional(10.0),
                text_color,
            );

            if resp.clicked() {
                *active_tab = i;
            }
        }
    });
}

fn handle_resize(ctx: &egui::Context, app: &mut FileLensApp) {
    let edge_width = 6.0;

    let pointer = ctx
        .input(|i| i.pointer.latest_pos())
        .unwrap_or(egui::pos2(-1.0, -1.0));
    let inner = ctx
        .input(|i| i.viewport().inner_rect)
        .unwrap_or(egui::Rect::NOTHING);

    let window_width = inner.width();
    let window_height = inner.height();

    let on_right = pointer.x > window_width - edge_width && pointer.x <= window_width;
    let on_bottom = pointer.y > window_height - edge_width && pointer.y <= window_height;

    if !app.resizing {
        if on_right && on_bottom {
            ctx.set_cursor_icon(egui::CursorIcon::ResizeNwSe);
        } else if on_right {
            ctx.set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
        } else if on_bottom {
            ctx.set_cursor_icon(egui::CursorIcon::ResizeVertical);
        }
    }

    let pointer_down = ctx.input(|i| i.pointer.primary_down());
    let pointer_pressed = ctx.input(|i| i.pointer.primary_pressed());

    if pointer_pressed && !app.dragging {
        let edge = if on_right && on_bottom {
            ResizeEdge::BottomRight
        } else if on_right {
            ResizeEdge::Right
        } else if on_bottom {
            ResizeEdge::Bottom
        } else {
            ResizeEdge::None
        };

        if edge != ResizeEdge::None {
            app.resizing = true;
            app.resize_edge = edge;
            app.resize_start_cursor = cursor_screen();
            app.resize_start_rect =
                [inner.min.x, inner.min.y, window_width, window_height];
        }
    }

    if app.resizing && pointer_down {
        let cursor_now = cursor_screen();
        let scale = ctx.input(|i| i.viewport().native_pixels_per_point.unwrap_or(1.0));
        let dx = (cursor_now[0] - app.resize_start_cursor[0]) / scale;
        let dy = (cursor_now[1] - app.resize_start_cursor[1]) / scale;

        let mut new_width = app.resize_start_rect[2];
        let mut new_height = app.resize_start_rect[3];

        match app.resize_edge {
            ResizeEdge::Right => new_width += dx,
            ResizeEdge::Bottom => new_height += dy,
            ResizeEdge::BottomRight => {
                new_width += dx;
                new_height += dy;
            }
            ResizeEdge::None => {}
        }

        new_width = new_width.clamp(400.0, 800.0);
        new_height = new_height.clamp(200.0, 900.0);

        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            new_width, new_height,
        )));

        match app.resize_edge {
            ResizeEdge::BottomRight => ctx.set_cursor_icon(egui::CursorIcon::ResizeNwSe),
            ResizeEdge::Right => ctx.set_cursor_icon(egui::CursorIcon::ResizeHorizontal),
            ResizeEdge::Bottom => ctx.set_cursor_icon(egui::CursorIcon::ResizeVertical),
            _ => {}
        }
    }

    if app.resizing && !pointer_down {
        app.resizing = false;
        app.resize_edge = ResizeEdge::None;
    }
}

impl eframe::App for FileLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(ctx);
        handle_resize(ctx, self);

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.should_close = true;
        }

        let has_focus = ctx.input(|i| i.viewport().focused.unwrap_or(true));
        if !self.first_frame && self.had_focus_last_frame && !has_focus && !self.pinned {
            self.should_close = true;
        }
        self.had_focus_last_frame = has_focus;
        self.first_frame = false;

        if self.should_close {
            self.cancel.store(true, Ordering::Relaxed);

            if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
                self.config.window_height = rect.height();
                self.config.window_width = rect.width();
            }
            self.config.last_tab = self.active_tab;
            self.config.save();

            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(Theme::BG)
                    .inner_margin(egui::Margin::same(0.0)),
            )
            .show(ctx, |ui| {
                draw_title_bar(ui, &self.file_name.clone(), self);

                draw_tab_bar(ui, &self.tabs, &mut self.active_tab);

                let active = self.active_tab;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                        egui::Frame::default()
                            .fill(egui::Color32::TRANSPARENT)
                            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                            .show(ui, |ui| {
                                if let Some(tab) = self.tabs.get_mut(active) {
                                    tab.ui(ui, &ctx.clone());
                                }
                            });
                    });
            });

        if let Some(rect) = ctx.input(|i| i.viewport().inner_rect) {
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("resize_grip"),
            ));
            let corner = rect.max;
            for i in 0..3 {
                let offset = 4.0 + i as f32 * 3.0;
                painter.line_segment(
                    [
                        egui::pos2(corner.x - offset, corner.y),
                        egui::pos2(corner.x, corner.y - offset),
                    ],
                    egui::Stroke::new(1.0, egui::Color32::from_rgb(0x3A, 0x3A, 0x3A)),
                );
            }
        }
    }
}