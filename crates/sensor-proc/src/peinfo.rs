//! Lecture best-effort du champ PE `OriginalFilename` (ressource de version) de
//! l'image d'un processus — clé de la détection de masquerading (binaire renommé) :
//! le nom d'origine inscrit dans le PE survit au renommage du fichier sur disque.
//!
//! Best-effort : un binaire sans ressource de version (fréquent hors Microsoft),
//! un chemin illisible ou toute erreur renvoient une chaîne vide (aucune alerte).

/// Renvoie le `OriginalFilename` du PE situé à `path`, ou "" si indisponible.
#[cfg(windows)]
pub fn original_file_name_of(path: &str) -> String {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    if path.is_empty() {
        return String::new();
    }
    let to_wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let wpath = to_wide(path);

    // SÛRETÉ : appels FFI Win32 version.dll. `buf` reste vivant tant qu'on lit les
    // pointeurs qu'il contient ; les sous-blocs large restent en portée le temps des
    // appels VerQueryValueW.
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), None);
        if size == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), 0, size, buf.as_mut_ptr() as *mut _)
            .is_err()
        {
            return String::new();
        }

        // 1) Table de traduction (langue + page de code) : \VarFileInfo\Translation.
        let trans_sub = to_wide("\\VarFileInfo\\Translation");
        let mut trans_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut trans_len: u32 = 0;
        let ok = VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(trans_sub.as_ptr()),
            &mut trans_ptr,
            &mut trans_len,
        );
        if !ok.as_bool() || trans_ptr.is_null() || trans_len < 4 {
            return String::new();
        }
        // Premier couple (u16 langue, u16 page de code).
        let lang = *(trans_ptr as *const u16);
        let codepage = *((trans_ptr as *const u16).add(1));

        // 2) Valeur : \StringFileInfo\{lang:04x}{codepage:04x}\OriginalFilename.
        let sub = format!("\\StringFileInfo\\{lang:04x}{codepage:04x}\\OriginalFilename");
        let sub_w = to_wide(&sub);
        let mut val_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut val_len: u32 = 0;
        let ok = VerQueryValueW(
            buf.as_ptr() as *const _,
            PCWSTR(sub_w.as_ptr()),
            &mut val_ptr,
            &mut val_len,
        );
        if !ok.as_bool() || val_ptr.is_null() || val_len == 0 {
            return String::new();
        }
        // val_len = nombre de caractères larges (NUL compris).
        let chars = std::slice::from_raw_parts(val_ptr as *const u16, val_len as usize);
        String::from_utf16_lossy(chars)
            .trim_end_matches('\0')
            .trim()
            .to_string()
    }
}

/// Hors Windows : pas de ressource de version PE, donc jamais de nom d'origine.
#[cfg(not(windows))]
pub fn original_file_name_of(_path: &str) -> String {
    String::new()
}
