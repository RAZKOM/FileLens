fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();

        let icon_path = if std::path::Path::new("assets/filelens.ico").exists() {
            Some("assets/filelens.ico")
        } else if std::path::Path::new("assets/icon.ico").exists() {
            Some("assets/icon.ico")
        } else {
            println!("cargo:warning=No icon found at assets/filelens.ico or assets/icon.ico — building without exe icon");
            None
        };

        if let Some(icon) = icon_path {
            res.set_icon(icon);
        }

        res.compile().expect("Failed to compile Windows resources");
    }
}