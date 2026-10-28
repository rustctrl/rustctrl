#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Connecting,
    Connected { bootstrap_required: Option<bool> },
    Unreachable,
}

impl ServerStatus {
    pub fn show_bootstrap_notice(self) -> bool {
        matches!(
            self,
            Self::Connected {
                bootstrap_required: Some(true)
            }
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitDecision {
    AlreadySubmitting,
    Invalid(&'static str),
    Submit,
}

pub fn submit_decision(username: &str, password: &str, in_flight: bool) -> SubmitDecision {
    if in_flight {
        SubmitDecision::AlreadySubmitting
    } else if let Err(error) = validate_login(username, password) {
        SubmitDecision::Invalid(error)
    } else {
        SubmitDecision::Submit
    }
}

pub fn validate_login(username: &str, password: &str) -> Result<(), &'static str> {
    if username.trim().is_empty() || password.is_empty() {
        Err("Username and password are required.")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_notice_requires_an_explicit_server_response() {
        assert!(
            ServerStatus::Connected {
                bootstrap_required: Some(true)
            }
            .show_bootstrap_notice()
        );
        assert!(
            !ServerStatus::Connected {
                bootstrap_required: Some(false)
            }
            .show_bootstrap_notice()
        );
        assert!(
            !ServerStatus::Connected {
                bootstrap_required: None
            }
            .show_bootstrap_notice()
        );
        assert!(!ServerStatus::Connecting.show_bootstrap_notice());
        assert!(!ServerStatus::Unreachable.show_bootstrap_notice());
    }

    #[test]
    fn submission_moves_from_validation_to_in_flight_and_retry() {
        assert!(matches!(
            submit_decision("", "", false),
            SubmitDecision::Invalid(_)
        ));
        assert_eq!(
            submit_decision("alice", "secret", false),
            SubmitDecision::Submit
        );
        assert_eq!(
            submit_decision("alice", "secret", true),
            SubmitDecision::AlreadySubmitting
        );
        assert_eq!(
            submit_decision("alice", "secret", false),
            SubmitDecision::Submit
        );
    }

    #[test]
    fn credentials_require_a_nonblank_username_and_password() {
        assert!(validate_login("  ", "secret").is_err());
        assert!(validate_login("alice", "").is_err());
        assert!(validate_login("alice", "secret").is_ok());
    }
}
