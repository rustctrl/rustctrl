#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Fleet,
    Remote,
    Accounts,
    Deployment,
    Audit,
}

impl Route {
    pub fn label(self) -> &'static str {
        match self {
            Self::Fleet => "Fleet Inventory",
            Self::Remote => "Remote Sessions",
            Self::Accounts => "Staff Accounts",
            Self::Deployment => "Agent Deployment",
            Self::Audit => "Audit History",
        }
    }

    fn allowed(self, role: &str) -> bool {
        matches!(self, Self::Fleet | Self::Remote) || role == "admin"
    }
}

pub struct Navigation {
    active: Route,
    pub collapsed: bool,
}

impl Default for Navigation {
    fn default() -> Self {
        Self {
            active: Route::Fleet,
            collapsed: false,
        }
    }
}

impl Navigation {
    pub fn routes(role: &str) -> impl Iterator<Item = Route> + '_ {
        [
            Route::Fleet,
            Route::Remote,
            Route::Accounts,
            Route::Deployment,
            Route::Audit,
        ]
        .into_iter()
        .filter(move |route| route.allowed(role))
    }

    pub fn active(&self, role: &str) -> Route {
        if self.active.allowed(role) {
            self.active
        } else {
            Route::Fleet
        }
    }

    pub fn select(&mut self, route: Route, role: &str) {
        if route.allowed(role) {
            self.active = route;
        }
    }

    pub fn reset(&mut self) {
        self.active = Route::Fleet;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_only_receive_allowed_destinations() {
        assert_eq!(
            Navigation::routes("admin").collect::<Vec<_>>(),
            vec![
                Route::Fleet,
                Route::Remote,
                Route::Accounts,
                Route::Deployment,
                Route::Audit
            ]
        );
        assert_eq!(
            Navigation::routes("operator").collect::<Vec<_>>(),
            vec![Route::Fleet, Route::Remote]
        );
        assert_eq!(
            Navigation::routes("unknown").collect::<Vec<_>>(),
            vec![Route::Fleet, Route::Remote]
        );
    }

    #[test]
    fn route_selection_respects_current_role_and_reset() {
        let mut nav = Navigation::default();
        nav.select(Route::Deployment, "admin");
        assert_eq!(nav.active("admin"), Route::Deployment);
        assert_eq!(nav.active("operator"), Route::Fleet);
        nav.select(Route::Accounts, "operator");
        assert_eq!(nav.active("operator"), Route::Fleet);
        nav.select(Route::Remote, "operator");
        assert_eq!(nav.active("operator"), Route::Remote);
        nav.reset();
        assert_eq!(nav.active("admin"), Route::Fleet);
    }
}
