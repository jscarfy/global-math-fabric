use chrono::{Local, Timelike, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuietHours {
    /// local time, 0..23
    pub start_hour: u8,
    pub end_hour: u8,
    /// if true, policy pauses during these hours
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunPolicy {
    /// only run when user explicitly opted in (default true)
    pub require_opt_in: bool,

    /// pause if on battery (best-effort detection), default true
    pub only_when_on_ac_power: bool,

    /// pause if battery percent < min (best-effort), default 30
    pub min_battery_percent: u8,

    /// cap CPU usage by sleeping between polls (coarse), default 5s loop already
    pub min_loop_seconds: u64,

    /// local quiet hours (pause), default disabled
    pub quiet_hours: QuietHours,

    /// allow manual pause switch
    pub paused: bool,
}

impl Default for RunPolicy {
    fn default() -> Self {
        Self {
            require_opt_in: true,
            only_when_on_ac_power: true,
            min_battery_percent: 30,
            min_loop_seconds: 5,
            quiet_hours: QuietHours { start_hour: 23, end_hour: 7, enabled: false },
            paused: false,
        }
    }
}

/// True if now is within quiet hours (local time). Interval can wrap midnight.
pub fn in_quiet_hours(q: &QuietHours) -> bool {
    if !q.enabled { return false; }
    let h = Local::now().hour() as u8;
    if q.start_hour == q.end_hour { return true; }
    if q.start_hour < q.end_hour {
        h >= q.start_hour && h < q.end_hour
    } else {
        // wraps midnight
        h >= q.start_hour || h < q.end_hour
    }
}

/// platform best-effort: (on_ac_power, battery_percent)
pub fn power_status() -> (Option<bool>, Option<u8>) {
    // We intentionally avoid heavy platform APIs; use command probing best-effort.
    // If unknown => None (policy treats as "not allowed" when strict).
    #[cfg(target_os="macos")]
    {
        // pmset -g batt
        if let Ok(out) = std::process::Command::new("pmset").args(["-g","batt"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            let on_ac = s.contains("AC Power");
            let pct = s.split('%').next().and_then(|left| left.rsplit_whitespace().next())
                .and_then(|x| x.parse::<u8>().ok());
            return (Some(on_ac), pct);
        }
    }
    #[cfg(target_os="linux")]
    {
        // upower -i $(upower -e | grep BAT | head -n1)
        // Parse "percentage:" and "state:"
        if let Ok(list) = std::process::Command::new("sh").arg("-lc")
            .arg("upower -e | grep -i BAT | head -n1").output()
        {
            let dev = String::from_utf8_lossy(&list.stdout).trim().to_string();
            if !dev.is_empty() {
                if let Ok(out) = std::process::Command::new("upower").args(["-i",&dev]).output() {
                    let s = String::from_utf8_lossy(&out.stdout).to_string();
                    let pct = s.lines().find(|l| l.trim().starts_with("percentage:"))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|v| v.trim().trim_end_matches('%').to_string())
                        .and_then(|v| v.parse::<u8>().ok());
                    let state = s.lines().find(|l| l.trim().starts_with("state:"))
                        .and_then(|l| l.split(':').nth(1)).map(|v| v.trim().to_string());
                    let on_ac = match state.as_deref() {
                        Some("charging") | Some("fully-charged") => Some(true),
                        Some("discharging") => Some(false),
                        _ => None
                    };
                    return (on_ac, pct);
                }
            }
        }
    }
    #[cfg(target_os="windows")]
    {
        // PowerShell Get-CimInstance Win32_Battery (best effort)
        if let Ok(out) = std::process::Command::new("powershell")
            .args(["-NoProfile","-Command",
                   "try { $b=Get-CimInstance -ClassName Win32_Battery | Select-Object -First 1; if ($null -eq $b) { exit 0 } ; $pct=$b.EstimatedChargeRemaining; $st=$b.BatteryStatus; Write-Output \"$pct $st\" } catch { }"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                let parts: Vec<_> = s.split_whitespace().collect();
                let pct = parts.get(0).and_then(|x| x.parse::<u8>().ok());
                // BatteryStatus: 2=charging, 3=fully charged, 1=discharging (common)
                let on_ac = parts.get(1).and_then(|x| x.parse::<u32>().ok()).and_then(|st| {
                    match st { 2|3 => Some(true), 1 => Some(false), _ => None }
                });
                return (on_ac, pct);
            }
        }
    }
    (None, None)
}

pub fn policy_allows_run(p: &RunPolicy) -> bool {
    if p.paused { return false; }
    if in_quiet_hours(&p.quiet_hours) { return false; }

    if p.only_when_on_ac_power || p.min_battery_percent > 0 {
        let (on_ac, pct) = power_status();
        if p.only_when_on_ac_power {
            // strict: if unknown => do not run
            if on_ac != Some(true) { return false; }
        }
        if p.min_battery_percent > 0 {
            if let Some(x) = pct {
                if x < p.min_battery_percent { return false; }
            } else {
                // unknown => conservative stop
                return false;
            }
        }
    }
    true
}
