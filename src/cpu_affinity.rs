/// Process CPU affinity on Windows (`SetProcessAffinityMask`).

const MAX_AFFINITY_BITS: usize = 64;

pub fn logical_cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
        .min(MAX_AFFINITY_BITS)
}

/// Bitmask of logical CPUs `2..n` (bits 0 and 1 cleared). `None` if nothing to set.
pub fn build_mask_excluding_0_and_1(logical_cpu_count: usize) -> Option<usize> {
    if logical_cpu_count <= 2 {
        return None;
    }
    let n = logical_cpu_count.min(MAX_AFFINITY_BITS);
    let mut mask = 0usize;
    for i in 2..n {
        mask |= 1usize << i;
    }
    if mask == 0 {
        None
    } else {
        Some(mask)
    }
}

/// Parse user spec: `0` or `0-5` (inclusive range). Indices must be `< n`.
pub fn parse_cpu_affinity_spec(spec: &str, n: usize) -> anyhow::Result<Vec<u32>> {
    let s = spec.trim();
    if s.is_empty() {
        anyhow::bail!("cpu affinity: spec is empty");
    }
    if n == 0 {
        anyhow::bail!("cpu affinity: no logical CPUs reported");
    }

    let mut indices = Vec::new();
    if let Some((a, b)) = s.split_once('-') {
        let start: u32 = a
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("cpu affinity: invalid range start"))?;
        let end: u32 = b
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("cpu affinity: invalid range end"))?;
        if start > end {
            anyhow::bail!("cpu affinity: range start ({start}) must be <= end ({end})");
        }
        for i in start..=end {
            if i as usize >= n {
                anyhow::bail!("cpu affinity: logical CPU {i} out of range (0..{})", n - 1);
            }
            indices.push(i);
        }
    } else {
        let i: u32 = s
            .parse()
            .map_err(|_| anyhow::anyhow!("cpu affinity: expected a number or range like 0-5"))?;
        if i as usize >= n {
            anyhow::bail!("cpu affinity: logical CPU {i} out of range (0..{})", n - 1);
        }
        indices.push(i);
    }

    if indices.is_empty() {
        anyhow::bail!("cpu affinity: no CPUs selected");
    }
    Ok(indices)
}

/// Normalize spec for storage (trim; range unchanged; single number as decimal).
pub fn normalize_cpu_affinity_spec(spec: &str) -> anyhow::Result<String> {
    let s = spec.trim();
    if s.is_empty() {
        anyhow::bail!("cpu affinity: spec is empty");
    }
    if let Some((a, b)) = s.split_once('-') {
        let start: u32 = a
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range"))?;
        let end: u32 = b
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range"))?;
        if start > end {
            anyhow::bail!("cpu affinity: invalid range");
        }
        Ok(format!("{start}-{end}"))
    } else {
        let i: u32 = s
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid CPU number"))?;
        Ok(i.to_string())
    }
}

pub fn mask_from_indices(indices: &[u32]) -> anyhow::Result<usize> {
    let mut mask = 0usize;
    for &i in indices {
        mask |= 1usize << i;
    }
    if mask == 0 {
        anyhow::bail!("cpu affinity: resulting mask is empty");
    }
    Ok(mask)
}

pub fn resolve_mask(spec: &str, n: usize) -> anyhow::Result<usize> {
    if spec.trim().is_empty() {
        build_mask_excluding_0_and_1(n).ok_or_else(|| {
            if n <= 2 {
                anyhow::anyhow!(
                    "cpu affinity: default (exclude 0,1) needs more than 2 logical CPUs (n={n})"
                )
            } else {
                anyhow::anyhow!("cpu affinity: default mask is empty")
            }
        })
    } else {
        let indices = parse_cpu_affinity_spec(spec, n)?;
        mask_from_indices(&indices)
    }
}

#[cfg(windows)]
pub fn apply_process_affinity_mask(mask: usize) -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessAffinityMask};

    unsafe {
        SetProcessAffinityMask(GetCurrentProcess(), mask)
            .ok()
            .context("SetProcessAffinityMask failed")?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_process_affinity_mask(_mask: usize) -> anyhow::Result<()> {
    Ok(())
}

pub fn apply_cpu_affinity_from_spec(spec: &str) -> anyhow::Result<usize> {
    let n = logical_cpu_count();
    if n > MAX_AFFINITY_BITS {
        anyhow::bail!(
            "cpu affinity: {n} logical CPUs exceeds supported mask width ({MAX_AFFINITY_BITS})"
        );
    }
    let mask = resolve_mask(spec, n)?;
    apply_process_affinity_mask(mask)?;
    Ok(mask)
}

pub fn apply_startup_cpu_affinity(spec: &str) {
    #[cfg(windows)]
    {
        let n = logical_cpu_count();
        let spec_trim = spec.trim();

        if n > MAX_AFFINITY_BITS {
            eprintln!(
                "{}",
                crate::term_style::fmt_info_line(format_args!(
                    " CPU affinity skipped: {n} logical CPUs (max {MAX_AFFINITY_BITS} for process mask)"
                ))
            );
            return;
        }

        if spec_trim.is_empty() && n <= 2 {
            eprintln!(
                "{}",
                crate::term_style::fmt_info_line(format_args!(
                    " CPU affinity skipped: {n} logical CPU(s); need more than 2 for default exclude 0,1"
                ))
            );
            return;
        }

        match apply_cpu_affinity_from_spec(spec) {
            Ok(mask) => {
                let label = if spec_trim.is_empty() {
                    format!("logical CPUs 0–1 excluded (default, n={n})")
                } else {
                    format!("spec \"{spec_trim}\" (n={n})")
                };
                eprintln!(
                    "{}",
                    crate::term_style::fmt_info_line(format_args!(
                        " Process CPU affinity: {label}, mask=0x{mask:X}"
                    ))
                );
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    crate::term_style::fmt_info_line(format_args!(
                        " Could not set process CPU affinity: {e}"
                    ))
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_mask_excluding_0_and_1, mask_from_indices, parse_cpu_affinity_spec, resolve_mask,
    };

    #[test]
    fn mask_n8_excludes_0_and_1() {
        assert_eq!(build_mask_excluding_0_and_1(8), Some(0xFC));
    }

    #[test]
    fn mask_n3_only_cpu2() {
        assert_eq!(build_mask_excluding_0_and_1(3), Some(0b100));
    }

    #[test]
    fn mask_n2_none() {
        assert_eq!(build_mask_excluding_0_and_1(2), None);
    }

    #[test]
    fn mask_n1_none() {
        assert_eq!(build_mask_excluding_0_and_1(1), None);
    }

    #[test]
    fn resolve_default_n8() {
        assert_eq!(resolve_mask("", 8).unwrap(), 0xFC);
    }

    #[test]
    fn parse_single_and_range() {
        assert_eq!(parse_cpu_affinity_spec("0", 8).unwrap(), vec![0]);
        assert_eq!(
            parse_cpu_affinity_spec("0-5", 8).unwrap(),
            vec![0, 1, 2, 3, 4, 5]
        );
        assert_eq!(mask_from_indices(&[0, 1, 2, 3, 4, 5]).unwrap(), 0x3F);
    }

    #[test]
    fn parse_out_of_range() {
        assert!(parse_cpu_affinity_spec("5", 4).is_err());
    }
}
