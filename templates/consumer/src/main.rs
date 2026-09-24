//! Minimal consumer entry point: implement `CommandExecutor`, then serve.

use tpt_privd_daemon::{Config, run_with};
use tpt_privd_envelope::{Command, CommandError, CommandKind, CommandSuccess, ErrorCode};
use tpt_privd_policy::{CommandExecutor, PolicyViolation};

/// Domain kinds must start at `CommandKind::CUSTOM_START` (0x8000_0000).
pub const KIND_REBOOT: CommandKind = CommandKind(CommandKind::CUSTOM_START);

pub struct DomainExecutor;

impl CommandExecutor for DomainExecutor {
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation> {
        match cmd.kind {
            CommandKind::NOP | CommandKind::ECHO | CommandKind::METRICS => Ok(()),
            KIND_REBOOT => Ok(()), // add real authorization here
            kind => Err(PolicyViolation::new(kind, "unknown command kind")),
        }
    }

    fn execute(&self, cmd: &Command) -> Result<CommandSuccess, CommandError> {
        match cmd.kind {
            CommandKind::NOP => Ok(CommandSuccess { payload: vec![] }),
            CommandKind::ECHO => Ok(CommandSuccess {
                payload: cmd.payload.clone(),
            }),
            CommandKind::METRICS => Ok(CommandSuccess {
                payload: tpt_privd_daemon::prometheus_text().into_bytes(),
            }),
            KIND_REBOOT => {
                // Privileged domain work goes here.
                Ok(CommandSuccess {
                    payload: b"reboot-queued".to_vec(),
                })
            }
            kind => Err(CommandError::new(
                ErrorCode::ExecutionFailed,
                format!("unhandled kind {:#x}", kind.0),
            )),
        }
    }
}

fn main() {
    let config = Config::default();
    if let Err(e) = run_with(&config, &DomainExecutor) {
        eprintln!("daemon exited: {e}");
        std::process::exit(1);
    }
}
