# FileLens

Right-click any file on Windows. Get instant analysis: hashes, strings, hex, PE internals, metadata. All in a compact popup that disappears when you click away.



---

## Download

> **[Download FileLens for Windows →](https://github.com/RAZKOM/filelens/releases/latest)**

Unzip and run `filelens.exe --register`. No installer, no admin rights, nothing else needed.

Requires Windows 10 or 11.

---

## How it works

1. Run `filelens.exe` once. It registers itself in your right-click menu
2. Right-click any file in Explorer -> **Inspect with FileLens**
3. A dark popup appears at your cursor with tabs for everything you need
4. Click away and it's gone

That's it. No window management, no app to keep open.

**To keep it open:** click the pin button (small square next to the X). Pinned windows stay until you close them manually.

**To remove from right-click menu:** `filelens.exe --unregister`

---

## What it shows

**Info** — size, timestamps, entropy score, magic bytes, type detection, extension mismatch warnings. For PE files: architecture, subsystem, imports/exports count, signing status, compile timestamp.

**Hashes** — MD5, SHA-1, SHA-256 computed in parallel. Full width selectable fields, copy buttons.

**Strings** — every printable ASCII and UTF-16 string in the file. Filter by length, search live, sort by offset/length/category/alphabetical. Category pills color-code URLs, file paths, registry keys, IPs, and emails. Dedup toggle collapses repeats with count badges.

**PE** — section table with per-section entropy and flags, imports grouped by DLL with function names, exports list. Only appears for EXE/DLL files.

**Hex** — first 64KB as a hex dump. Click any byte for details. Zero bytes dimmed, ASCII sidebar.

**Meta** — PDF properties, Office doc metadata (DOCX/XLSX/PPTX), JPEG EXIF, PNG chunk data. Only appears for supported formats.

Tabs are smart — you only see what's relevant to the file you're inspecting.

---

## Build from source

```powershell
# Requires Rust stable + MSVC build tools
cargo build --release

```

Output: `target/release/filelens.exe`

Optional: place an icon at `assets/filelens.ico` and it gets embedded into the exe automatically.

---

### Adding a new tab

1. Create `src/analysis/yourtab.rs` implementing the `AnalysisTab` trait
2. Accept `Arc<AtomicBool>` cancel flag in your constructor
3. Add `pub mod yourtab;` to `src/analysis/mod.rs`
4. Add `Box::new(yourtab::YourTab::new(cancel.clone()))` to `create_tabs_for()` in `mod.rs`
5. Optionally override `relevant_for(&self, path) -> bool` to conditionally show the tab

### The AnalysisTab trait

```rust
pub trait AnalysisTab: Send {
    fn name(&self) -> &str;                                    // Tab label
    fn run(&mut self, path: &Path);                            // Start background work
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context); // Draw tab contents
    fn is_loading(&self) -> bool;                              // Show spinner in tab bar
    fn relevant_for(&self, _path: &Path) -> bool { true }     // Show/hide tab per file
}
```

## License

MIT — free to use, modify, and distribute.
