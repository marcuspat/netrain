//! Terminal set-up that always gets undone.
//!
//! Raw mode and the alternate screen must be left on every exit path -
//! normal return, `?` error, or panic - otherwise the user's shell is left
//! without echo and with a garbled screen.

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use crossterm::{
    cursor::Show,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static HOOK: Once = Once::new();

/// Undo raw mode and the alternate screen. Idempotent and safe to call from
/// a panic hook: only acts if the terminal is currently set up.
pub fn restore() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    }
}

/// Is the terminal currently in TUI mode?
#[cfg(test)]
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// Owns the TUI terminal; restores the user's terminal when dropped.
pub struct TerminalGuard {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        // Restore *before* the panic message is printed, so it is readable
        // and lands on the normal screen.
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore();
                previous(info);
            }));
        });

        enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen) {
            restore();
            return Err(e);
        }
        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(e) => {
                restore();
                Err(e)
            }
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_is_idempotent_and_clears_the_flag() {
        // No real terminal in the test harness: exercise the state machine.
        ACTIVE.store(true, Ordering::SeqCst);
        restore();
        assert!(!is_active());
        restore(); // second call is a no-op
        assert!(!is_active());
    }
}
