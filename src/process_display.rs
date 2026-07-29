//! Per-process Task Manager label (`SetProcessDescription`), independent of exe file name.

#[cfg(windows)]
pub fn set_task_manager_name(name: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::GetCurrentProcess;

    type SetProcessDescriptionFn = unsafe extern "system" fn(
        windows::Win32::Foundation::HANDLE,
        PCWSTR,
    ) -> windows::core::HRESULT;

    unsafe {
        let Ok(kernel) = GetModuleHandleA(windows::core::s!("kernel32.dll")) else {
            return;
        };
        let Some(proc) = GetProcAddress(kernel, windows::core::s!("SetProcessDescription")) else {
            return;
        };
        let set_desc: SetProcessDescriptionFn = std::mem::transmute(proc);
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);
        let _ = set_desc(GetCurrentProcess(), PCWSTR(wide.as_ptr()));
    }
}

#[cfg(not(windows))]
pub fn set_task_manager_name(_name: &str) {}
