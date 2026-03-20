
#[cfg(target_os = "windows")]
pub mod win32 {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::*;

    const FILE_SHELL_KEY: &str = r"Software\Classes\*\shell\FileLens";
    const FILE_COMMAND_KEY: &str = r"Software\Classes\*\shell\FileLens\command";
    const DIR_SHELL_KEY: &str = r"Software\Classes\directory\shell\FileLens";
    const DIR_COMMAND_KEY: &str = r"Software\Classes\directory\shell\FileLens\command";

    fn set_reg_value(hkey: HKEY, subkey: &str, name: Option<&str>, value: &str) -> Result<(), String> {
        unsafe {
            let subkey_h = HSTRING::from(subkey);
            let mut key = HKEY::default();

            let result = RegCreateKeyExW(
                hkey,
                &subkey_h,
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            );

            if result.is_err() {
                return Err(format!("Failed to create registry key '{}': {:?}", subkey, result));
            }

            let name_hstring: Option<HSTRING> = name.map(|n| HSTRING::from(n));

            let data: Vec<u8> = value
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .flat_map(|w| w.to_le_bytes())
                .collect();

            let name_pcwstr = PCWSTR(
                name_hstring.as_ref().map_or(std::ptr::null(), |h| h.as_ptr()),
            );

            let result = RegSetValueExW(
                key,
                name_pcwstr,
                0,
                REG_SZ,
                Some(&data),
            );

            let _ = RegCloseKey(key);

            if result.is_err() {
                return Err(format!("Failed to set registry value: {:?}", result));
            }

            Ok(())
        }
    }

    fn delete_reg_tree(hkey: HKEY, subkey: &str) -> Result<(), String> {
        unsafe {
            let subkey_h = HSTRING::from(subkey);
            let pcwstr = PCWSTR(subkey_h.as_ptr());
            let result = RegDeleteTreeW(hkey, pcwstr);

            if result.is_err() {
                return Ok(());
            }

            let _ = RegDeleteKeyW(hkey, &subkey_h);
            Ok(())
        }
    }

    pub fn register_context_menu() -> Result<(), String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Cannot determine exe path: {e}"))?;
        let exe_str = exe_path.to_string_lossy();

        let command = format!("\"{}\" \"%1\"", exe_str);
        let icon_value = format!("{},0", exe_str);

        set_reg_value(HKEY_CURRENT_USER, FILE_SHELL_KEY, None, "Inspect with FileLens")?;
        set_reg_value(HKEY_CURRENT_USER, FILE_SHELL_KEY, Some("Icon"), &icon_value)?;
        set_reg_value(HKEY_CURRENT_USER, FILE_COMMAND_KEY, None, &command)?;

        set_reg_value(HKEY_CURRENT_USER, DIR_SHELL_KEY, None, "Inspect with FileLens")?;
        set_reg_value(HKEY_CURRENT_USER, DIR_SHELL_KEY, Some("Icon"), &icon_value)?;
        set_reg_value(HKEY_CURRENT_USER, DIR_COMMAND_KEY, None, &command)?;

        Ok(())
    }

    pub fn unregister_context_menu() -> Result<(), String> {
        delete_reg_tree(HKEY_CURRENT_USER, FILE_SHELL_KEY)?;
        delete_reg_tree(HKEY_CURRENT_USER, DIR_SHELL_KEY)?;
        Ok(())
    }

    pub fn is_registered() -> bool {
        unsafe {
            let subkey_h = HSTRING::from(FILE_SHELL_KEY);
            let mut key = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                &subkey_h,
                0,
                KEY_READ,
                &mut key,
            );

            if result.is_ok() {
                let _ = RegCloseKey(key);
                true
            } else {
                false
            }
        }
    }
}

/// Stub implementations for non-Windows platforms (for development/testing).
#[cfg(not(target_os = "windows"))]
pub mod win32 {
    pub fn register_context_menu() -> Result<(), String> {
        eprintln!("[stub] Would register context menu on Windows");
        Ok(())
    }

    pub fn unregister_context_menu() -> Result<(), String> {
        eprintln!("[stub] Would unregister context menu on Windows");
        Ok(())
    }

    pub fn is_registered() -> bool {
        false
    }
}