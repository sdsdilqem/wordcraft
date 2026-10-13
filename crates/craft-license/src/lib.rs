//! License check shared by the Craft apps and the Creative Cloud launcher. See README.md.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

/// The license panel's API. The signing key is fetched from here, so a key changed in the panel
/// reaches every app on its next check; nothing key-related is built into the apps.
/// `CRAFT_LICENSE_API` at build time overrides it (for a test server).
const API: &str = match option_env!("CRAFT_LICENSE_API") {
    Some(a) => a,
    None => "https://lisenziyam.az/adobe/api",
};
/// How often a running app asks the server for a fresh license.
const REFRESH_EVERY: u64 = 6 * 3600;
/// How much a clock may run backwards (DST changes, NTP corrections) before it counts as tampering.
const CLOCK_SLACK: u64 = 3600;
/// How long a running app stays open after its license expires mid-session.
const GRACE_CLOSE: Duration = Duration::from_secs(10 * 60);

/// What is saved on disk: the signed payload plus the sign-in token used to refresh it.
#[derive(Serialize, Deserialize, Clone)]
pub struct LicenseFile {
    pub payload: String,
    pub sig: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Payload {
    pub sub: String,
    pub dev: String,
    pub iat: u64,
    pub exp: Option<u64>,
    pub refresh_by: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Problem {
    /// No license file: the user never signed in to the launcher on this computer.
    Missing,
    /// The file was edited, signed by another key, or copied from another computer.
    Invalid,
    /// The license's end date has passed (or the server says it expired).
    Expired,
    /// The server says the license was suspended.
    Suspended,
    /// The app could not reach the server for longer than the offline allowance.
    Offline,
    /// The app has never reached the license server on this computer, so it has no key yet.
    NoServer,
    /// The computer's clock was set back.
    Clock,
}

impl Problem {
    pub fn title(&self) -> &'static str {
        match self {
            Problem::Expired => "License Expired",
            Problem::Suspended => "License Suspended",
            _ => "License Required",
        }
    }

    pub fn message(&self, app: &str) -> String {
        match self {
            Problem::Missing => format!("{app} needs an active license. Open Creative Cloud and sign in with your license."),
            Problem::Invalid => format!("The license on this computer is not valid for {app}. Open Creative Cloud and sign in again."),
            Problem::Expired => format!("Your license has expired, so {app} can no longer be used. Contact your seller to renew it."),
            Problem::Suspended => format!("Your license was suspended, so {app} can no longer be used. Contact your seller."),
            Problem::Offline => format!("{app} could not check your license for too long. Connect to the internet and open Creative Cloud."),
            Problem::NoServer => format!(
                "{app} could not reach the license server ({API}). Check the internet connection or firewall and try again.\n\nDetails are in {}.",
                log_path().map(|p| p.display().to_string()).unwrap_or_default()
            ),
            Problem::Clock => "Your computer's date and time look wrong. Correct them and try again.".into(),
        }
    }
}

// ---------- locations ----------

fn data_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/ArtCraft"))
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("ArtCraft"))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/artcraft"))
    }
}

pub fn license_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("license.json"))
}

fn key_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("license-key"))
}

fn log_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("license.log"))
}

/// Keep the last few license-check errors on disk, so a failure can be diagnosed.
fn log(msg: &str) {
    let Some(path) = log_path() else { return };
    let old = fs::read_to_string(&path).unwrap_or_default();
    let keep: Vec<&str> = old.lines().rev().take(50).collect::<Vec<_>>().into_iter().rev().collect();
    let _ = fs::create_dir_all(path.parent().unwrap());
    let _ = fs::write(&path, format!("{}\n{} {msg}\n", keep.join("\n"), now()).trim_start());
}

fn clock_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("clock"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------- device ----------

/// Stable id of this computer (hashed so the raw hardware id never leaves it).
/// macOS: IOPlatformUUID. Windows: MachineGuid. Others: /etc/machine-id.
pub fn machine_id() -> String {
    let raw = raw_machine_id().unwrap_or_default();
    let digest = Sha256::digest(format!("artcraft-device:{}", raw.trim()).as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

fn raw_machine_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().find(|l| l.contains("IOPlatformUUID"))?;
        return line.split('"').nth(3).map(str::to_owned);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        return text.lines().find(|l| l.contains("MachineGuid"))?.split_whitespace().last().map(str::to_owned);
    }
    #[allow(unreachable_code)]
    fs::read_to_string("/etc/machine-id").ok()
}

// ---------- file ----------

pub fn read_file() -> Option<LicenseFile> {
    serde_json::from_slice(&fs::read(license_path()?).ok()?).ok()
}

pub fn write_file(f: &LicenseFile) -> std::io::Result<()> {
    let path = license_path().ok_or_else(|| std::io::Error::other("no data directory"))?;
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(f)?)?;
    fs::rename(tmp, path)
}

pub fn delete_file() {
    if let Some(p) = license_path() {
        let _ = fs::remove_file(p);
    }
}

/// Check the signature against `key` and that the license was issued for this computer.
pub fn verify(f: &LicenseFile, key: &str) -> Result<Payload, Problem> {
    verify_with(f, key, &machine_id())
}

fn verify_with(f: &LicenseFile, pubkey_b64: &str, device: &str) -> Result<Payload, Problem> {
    let key: [u8; 32] = B64.decode(pubkey_b64.trim()).ok().and_then(|k| k.try_into().ok()).ok_or(Problem::Invalid)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| Problem::Invalid)?;
    let payload = B64.decode(&f.payload).map_err(|_| Problem::Invalid)?;
    let sig: [u8; 64] = B64.decode(&f.sig).ok().and_then(|s| s.try_into().ok()).ok_or(Problem::Invalid)?;
    key.verify(&payload, &Signature::from_bytes(&sig)).map_err(|_| Problem::Invalid)?;
    let p: Payload = serde_json::from_slice(&payload).map_err(|_| Problem::Invalid)?;
    if p.dev != device {
        return Err(Problem::Invalid);
    }
    Ok(p)
}

/// The date checks on a verified payload at time `t`.
fn judge(p: &Payload, t: u64, last_seen: u64) -> Result<(), Problem> {
    if t + CLOCK_SLACK < last_seen || t + CLOCK_SLACK < p.iat {
        return Err(Problem::Clock);
    }
    if p.exp.is_some_and(|e| t >= e) {
        return Err(Problem::Expired);
    }
    if t >= p.refresh_by {
        return Err(Problem::Offline);
    }
    Ok(())
}

/// Remember the latest time seen, so a clock set back later is noticed.
fn note_clock(t: u64) -> u64 {
    let Some(path) = clock_path() else { return 0 };
    let last = fs::read_to_string(&path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0u64);
    if t > last {
        let _ = fs::create_dir_all(path.parent().unwrap());
        let _ = fs::write(&path, t.to_string());
    }
    last
}

// ---------- server ----------

fn agent() -> ureq::Agent {
    // A browser-like user agent: some shared hosts' firewalls (ModSecurity) refuse library defaults.
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("Mozilla/5.0 (compatible; ArtCraft-License/", env!("CARGO_PKG_VERSION"), ")"))
        .build()
}

fn api_allowed(api: &str) -> bool {
    api.starts_with("https://") || api.starts_with("http://127.0.0.1")
}

#[derive(Deserialize)]
struct KeyAnswer {
    ok: bool,
    #[serde(default)]
    public_key: String,
}

/// Tag binding a cached key to this computer, so the cache can't simply be swapped for a key
/// from somewhere else (basic protection; see README).
fn key_tag(key: &str, device: &str) -> String {
    let d = Sha256::digest(format!("artcraft-key:{device}:{}", key.trim()).as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_cached_key() -> Option<String> {
    let text = fs::read_to_string(key_path()?).ok()?;
    let (key, tag) = text.trim().split_once(' ')?;
    (key_tag(key, &machine_id()) == tag).then(|| key.to_owned())
}

fn cache_key(key: &str) {
    if let Some(path) = key_path() {
        let _ = fs::create_dir_all(path.parent().unwrap());
        let _ = fs::write(&path, format!("{} {}", key.trim(), key_tag(key, &machine_id())));
    }
}

/// The panel's current public key, fetched over HTTPS (and cached for offline use).
fn fetch_key() -> Option<String> {
    if !api_allowed(API) {
        return None;
    }
    let url = format!("{}/key.php", API.trim_end_matches('/'));
    let a: KeyAnswer = match agent().get(&url).call() {
        Ok(r) => match r.into_json() {
            Ok(a) => a,
            Err(e) => {
                log(&format!("{url}: answer is not the expected JSON ({e})"));
                return None;
            }
        },
        Err(ureq::Error::Status(code, _)) => {
            log(&format!("{url}: HTTP {code}"));
            return None;
        }
        Err(e) => {
            log(&format!("{url}: {e}"));
            return None;
        }
    };
    let valid = B64.decode(a.public_key.trim()).is_ok_and(|k| k.len() == 32);
    if !(a.ok && valid) {
        log(&format!("{url}: no valid public_key in the answer"));
        return None;
    }
    cache_key(&a.public_key);
    Some(a.public_key.trim().to_owned())
}

/// The key to check against: the server's when reachable, else the last one it gave.
fn current_key() -> Option<String> {
    fetch_key().or_else(read_cached_key)
}

#[derive(Deserialize)]
struct Answer {
    ok: bool,
    #[serde(default)]
    error: String,
    license: Option<LicenseFile>,
}

enum Refresh {
    Updated(LicenseFile),
    Refused(Problem),
    Unreachable,
}

/// Ask the server for a fresh license with the saved token.
fn refresh(f: &LicenseFile) -> Refresh {
    if f.token.is_empty() || !api_allowed(API) {
        return Refresh::Unreachable;
    }
    let res = agent().get(&format!("{}/license.php", API.trim_end_matches('/'))).set("Authorization", &format!("Bearer {}", f.token)).call();
    let resp = match res {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => {
            log(&format!("license.php: {e}"));
            return Refresh::Unreachable;
        }
    };
    let Ok(a) = resp.into_json::<Answer>() else { return Refresh::Unreachable };
    match (a.ok, a.license) {
        (true, Some(l)) => Refresh::Updated(LicenseFile { token: f.token.clone(), ..l }),
        _ => match a.error.as_str() {
            "expired" => Refresh::Refused(Problem::Expired),
            "suspended" => Refresh::Refused(Problem::Suspended),
            // A password reset or a removed device invalidates the token.
            "invalid_token" | "no_token" | "missing_device" => Refresh::Refused(Problem::Invalid),
            _ => Refresh::Unreachable,
        },
    }
}

/// Full check: fetch the key, read and verify the license, refresh it when due (or forced, or
/// when it was signed by a key the panel has since replaced), and judge the dates.
pub fn check(force_refresh: bool) -> Result<Payload, Problem> {
    let t = now();
    let last_seen = note_clock(t);
    let file = read_file().ok_or(Problem::Missing)?;
    // Never reached the server and no key from before: nothing to check against yet.
    let key = current_key().ok_or(Problem::NoServer)?;
    let verified = verify(&file, &key);
    let due = verified.as_ref().map_or(true, |p| force_refresh || t >= p.iat + REFRESH_EVERY);
    let p = if due {
        match refresh(&file) {
            Refresh::Updated(new) => match verify(&new, &key) {
                Ok(np) => {
                    let _ = write_file(&new);
                    np
                }
                Err(_) => verified?,
            },
            Refresh::Refused(problem) => {
                // Keep the token out of the way so a stale file can't be reused offline.
                delete_file();
                return Err(problem);
            }
            Refresh::Unreachable => verified?,
        }
    } else {
        verified?
    };
    judge(&p, t, last_seen)?;
    Ok(p)
}

// ---------- UI ----------

fn show(title: &str, message: &str) {
    #[cfg(all(feature = "dialog", any(target_os = "macos", target_os = "windows")))]
    {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title(title)
            .set_description(message)
            .set_buttons(rfd::MessageButtons::Ok)
            .show();
    }
    #[cfg(not(all(feature = "dialog", any(target_os = "macos", target_os = "windows"))))]
    eprintln!("{title}: {message}");
}

/// Call first thing in `main()`. Quits the process with a "License Expired" window when the
/// license is not valid, and keeps checking in the background while the app runs.
pub fn enforce(app_name: &'static str) {
    if let Err(problem) = check(true) {
        log(&format!("{app_name}: {problem:?}"));
        show(problem.title(), &problem.message(app_name));
        std::process::exit(2);
    }
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(REFRESH_EVERY));
        if let Err(problem) = check(true) {
            show(
                problem.title(),
                &format!("{}\n\nSave your work now: {app_name} will close in 10 minutes.", problem.message(app_name)),
            );
            thread::sleep(GRACE_CLOSE);
            std::process::exit(2);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(sk: &SigningKey, json: &str) -> LicenseFile {
        LicenseFile { payload: B64.encode(json), sig: B64.encode(sk.sign(json.as_bytes()).to_bytes()), token: String::new() }
    }

    fn key() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = B64.encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    const P: &str = r#"{"v":1,"sub":"u","dev":"d1","iat":1000,"exp":5000,"refresh_by":3000}"#;

    #[test]
    fn accepts_good_license() {
        let (sk, pk) = key();
        let p = verify_with(&signed(&sk, P), &pk, "d1").unwrap();
        assert_eq!(judge(&p, 2000, 1500), Ok(()));
    }

    #[test]
    fn rejects_tampering_and_other_devices() {
        let (sk, pk) = key();
        let mut f = signed(&sk, P);
        assert_eq!(verify_with(&f, &pk, "d2").unwrap_err(), Problem::Invalid);
        f.payload = B64.encode(P.replace("5000", "9999999999"));
        assert_eq!(verify_with(&f, &pk, "d1").unwrap_err(), Problem::Invalid);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(verify_with(&signed(&other, P), &pk, "d1").unwrap_err(), Problem::Invalid);
    }

    #[test]
    fn cached_key_is_bound_to_the_device() {
        let (_, pk) = key();
        assert_eq!(key_tag(&pk, "d1"), key_tag(&pk, "d1"));
        assert_ne!(key_tag(&pk, "d1"), key_tag(&pk, "d2"));
        assert_ne!(key_tag(&pk, "d1"), key_tag("AAAA", "d1"));
    }

    #[test]
    fn judges_dates() {
        let (sk, pk) = key();
        let p = verify_with(&signed(&sk, P), &pk, "d1").unwrap();
        assert_eq!(judge(&p, 3000, 0), Err(Problem::Offline));
        let long = P.replace("3000", "9000");
        let p2 = verify_with(&signed(&sk, &long), &pk, "d1").unwrap();
        assert_eq!(judge(&p2, 5000, 0), Err(Problem::Expired));
        assert_eq!(judge(&p, 2000, 2000 + CLOCK_SLACK + 1), Err(Problem::Clock));
        let unlimited = P.replace("\"exp\":5000", "\"exp\":null");
        let p3 = verify_with(&signed(&sk, &unlimited), &pk, "d1").unwrap();
        assert_eq!(judge(&p3, 2999, 0), Ok(()));
    }
}
