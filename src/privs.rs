//! Give up root as soon as it is no longer needed.
//!
//! Opening a capture needs privilege; reading packets from the already-open
//! handle does not. Everything after that point - parsing attacker-supplied
//! bytes, drawing them, writing them out - runs unprivileged, so a bug in a
//! parser cannot be turned into root.

use std::fmt;

/// The unprivileged account used when there is no invoking user to return to.
const NOBODY: u32 = 65534;

/// Outcome of [`drop_privileges`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privileges {
    /// We were not root; nothing to give up.
    Unprivileged { uid: u32 },
    /// Root was given up; now running as this user and group.
    Dropped { uid: u32, gid: u32 },
    /// Still root because the user asked for it (`--keep-privileges`).
    Kept,
}

impl fmt::Display for Privileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unprivileged { uid } => write!(f, "running as uid {uid}"),
            Self::Dropped { uid, gid } => write!(f, "dropped root, running as uid {uid} gid {gid}"),
            Self::Kept => write!(f, "still running as root (--keep-privileges)"),
        }
    }
}

/// Which account to become, given who we are and how we were started.
///
/// Under `sudo` this is the invoking user (from `SUDO_UID`/`SUDO_GID`), so
/// files and the terminal keep working as they would have without sudo.
/// A root login or a container has no such user, so `nobody` is used. A
/// `SUDO_UID` of 0 is not somewhere to drop *to*.
pub fn drop_target(
    euid: u32,
    sudo_uid: Option<&str>,
    sudo_gid: Option<&str>,
) -> Option<(u32, u32)> {
    if euid != 0 {
        return None;
    }
    let parse = |v: Option<&str>| {
        v.and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|id| *id != 0)
    };
    match (parse(sudo_uid), parse(sudo_gid)) {
        (Some(uid), Some(gid)) => Some((uid, gid)),
        (Some(uid), None) => Some((uid, uid)),
        _ => Some((NOBODY, NOBODY)),
    }
}

/// Drop root if we have it. Call once the capture is open.
#[cfg(unix)]
pub fn drop_privileges(keep: bool) -> Result<Privileges, String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let sudo_gid = std::env::var("SUDO_GID").ok();
    let Some((uid, gid)) = drop_target(euid, sudo_uid.as_deref(), sudo_gid.as_deref()) else {
        return Ok(Privileges::Unprivileged { uid: euid });
    };
    if keep {
        return Ok(Privileges::Kept);
    }

    let os_error = |what: &str| {
        format!(
            "cannot drop privileges ({what}): {}",
            std::io::Error::last_os_error()
        )
    };
    // SAFETY: plain libc calls with valid arguments. Order matters:
    // supplementary groups and the gid must go while we are still root,
    // the uid last.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(os_error("setgroups"));
        }
        if libc::setgid(gid) != 0 {
            return Err(os_error("setgid"));
        }
        if libc::setuid(uid) != 0 {
            return Err(os_error("setuid"));
        }
        // Prove it is irreversible; a drop that can be undone protects nothing.
        if libc::setuid(0) == 0 || libc::geteuid() == 0 {
            return Err("privileges could be regained after dropping them".to_string());
        }
    }
    Ok(Privileges::Dropped { uid, gid })
}

#[cfg(not(unix))]
pub fn drop_privileges(_keep: bool) -> Result<Privileges, String> {
    Ok(Privileges::Unprivileged { uid: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_root_has_nothing_to_drop() {
        assert_eq!(drop_target(1000, None, None), None);
        assert_eq!(drop_target(1000, Some("0"), Some("0")), None);
    }

    #[test]
    fn sudo_returns_to_the_invoking_user() {
        assert_eq!(
            drop_target(0, Some("1000"), Some("1001")),
            Some((1000, 1001))
        );
        assert_eq!(drop_target(0, Some(" 501 "), None), Some((501, 501)));
    }

    #[test]
    fn root_without_a_real_user_becomes_nobody() {
        assert_eq!(drop_target(0, None, None), Some((NOBODY, NOBODY)));
        // `sudo` run by root itself, or garbage in the environment, must
        // never result in "dropping" to uid 0.
        assert_eq!(drop_target(0, Some("0"), Some("0")), Some((NOBODY, NOBODY)));
        assert_eq!(
            drop_target(0, Some("root"), Some("wheel")),
            Some((NOBODY, NOBODY))
        );
        assert_eq!(
            drop_target(0, Some("-1"), Some("1000")),
            Some((NOBODY, NOBODY))
        );
        assert_eq!(
            drop_target(0, Some("99999999999"), None),
            Some((NOBODY, NOBODY))
        );
    }

    #[test]
    fn messages() {
        assert_eq!(
            Privileges::Dropped {
                uid: 1000,
                gid: 1000
            }
            .to_string(),
            "dropped root, running as uid 1000 gid 1000"
        );
        assert_eq!(
            Privileges::Unprivileged { uid: 501 }.to_string(),
            "running as uid 501"
        );
        assert!(Privileges::Kept.to_string().contains("--keep-privileges"));
    }
}
