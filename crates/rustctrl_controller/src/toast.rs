#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
    Warning,
}

impl ToastKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Error => "Error",
            Self::Info => "Info",
            Self::Warning => "Warning",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToastNotification {
    pub id: u64,
    pub kind: ToastKind,
    pub title: String,
    pub message: String,
    pub duration_ms: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ToastManager {
    next_id: u64,
    toasts: Vec<ToastNotification>,
}

impl ToastManager {
    pub const DEFAULT_DURATION_MS: u64 = 3000;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(
        &mut self,
        kind: ToastKind,
        title: impl Into<String>,
        message: impl Into<String>,
        created_at_ms: u64,
    ) -> u64 {
        self.push_with_duration(
            kind,
            title,
            message,
            Self::DEFAULT_DURATION_MS,
            created_at_ms,
        )
    }

    pub fn push_with_duration(
        &mut self,
        kind: ToastKind,
        title: impl Into<String>,
        message: impl Into<String>,
        duration_ms: u64,
        created_at_ms: u64,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.toasts.push(ToastNotification {
            id,
            kind,
            title: title.into(),
            message: message.into(),
            duration_ms,
            created_at_ms,
        });
        id
    }

    pub fn success(&mut self, title: impl Into<String>, message: impl Into<String>) -> u64 {
        let now_ms = current_unix_ms();
        self.push(ToastKind::Success, title, message, now_ms)
    }

    pub fn error(&mut self, title: impl Into<String>, message: impl Into<String>) -> u64 {
        let now_ms = current_unix_ms();
        self.push(ToastKind::Error, title, message, now_ms)
    }

    pub fn info(&mut self, title: impl Into<String>, message: impl Into<String>) -> u64 {
        let now_ms = current_unix_ms();
        self.push(ToastKind::Info, title, message, now_ms)
    }

    pub fn warning(&mut self, title: impl Into<String>, message: impl Into<String>) -> u64 {
        let now_ms = current_unix_ms();
        self.push(ToastKind::Warning, title, message, now_ms)
    }

    pub fn dismiss(&mut self, id: u64) {
        self.toasts.retain(|t| t.id != id);
    }

    pub fn clear(&mut self) {
        self.toasts.clear();
    }

    pub fn active_toasts(&self) -> &[ToastNotification] {
        &self.toasts
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.toasts
            .retain(|t| t.created_at_ms.saturating_add(t.duration_ms) > now_ms);
    }

    pub fn tick_now(&mut self) {
        self.tick(current_unix_ms());
    }
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toast_lifecycle_push_and_auto_dismiss() {
        let mut manager = ToastManager::new();
        assert!(manager.active_toasts().is_empty());

        let t1 = manager.push(
            ToastKind::Success,
            "Device Updated",
            "Reception Desktop renamed successfully",
            1000,
        );
        let t2 = manager.push(
            ToastKind::Error,
            "Connection Failed",
            "Timeout connecting to target",
            1500,
        );

        assert_eq!(manager.active_toasts().len(), 2);
        assert_eq!(manager.active_toasts()[0].id, t1);
        assert_eq!(manager.active_toasts()[0].kind, ToastKind::Success);
        assert_eq!(manager.active_toasts()[0].title, "Device Updated");
        assert_eq!(manager.active_toasts()[1].id, t2);

        // Advance time before expiry (default duration 3000ms, t1 created at 1000 -> expires at 4000)
        manager.tick(3500);
        assert_eq!(manager.active_toasts().len(), 2);

        // Advance past t1 expiry (4001ms), t2 created at 1500 expires at 4500
        manager.tick(4100);
        assert_eq!(manager.active_toasts().len(), 1);
        assert_eq!(manager.active_toasts()[0].id, t2);

        // Advance past t2 expiry
        manager.tick(4600);
        assert!(manager.active_toasts().is_empty());

        // Manual dismiss
        let t3 = manager.push(ToastKind::Info, "Exporting", "Package ready", 5000);
        assert_eq!(manager.active_toasts().len(), 1);
        manager.dismiss(t3);
        assert!(manager.active_toasts().is_empty());
    }

    #[test]
    fn toast_convenience_constructors() {
        let mut manager = ToastManager::new();
        manager.success("Success Title", "Success details");
        manager.error("Error Title", "Error details");
        manager.info("Info Title", "Info details");
        manager.warning("Warning Title", "Warning details");

        let active = manager.active_toasts();
        assert_eq!(active.len(), 4);
        assert_eq!(active[0].kind, ToastKind::Success);
        assert_eq!(active[1].kind, ToastKind::Error);
        assert_eq!(active[2].kind, ToastKind::Info);
        assert_eq!(active[3].kind, ToastKind::Warning);

        manager.clear();
        assert!(manager.active_toasts().is_empty());
    }
}
