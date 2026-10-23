use anyhow::Result;
use gpui::{App, Context, IntoElement, Render, Task, Window, WindowOptions, div, prelude::*, rgb};
use rustctrl_core::ControllerConfig;
use rustctrl_protocol::bootstrap::HealthRequest;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
struct Snapshot {
    status: String,
    devices: Option<u64>,
}
struct Dashboard {
    endpoint: String,
    status: Snapshot,
    _refresh: Task<()>,
}
impl Dashboard {
    fn new(endpoint: String, snapshot: Arc<Mutex<Snapshot>>, cx: &mut Context<Self>) -> Self {
        let refresh = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                let next = snapshot.try_lock().ok().map(|snapshot| snapshot.clone());
                if let Some(next) = next
                    && this
                        .update(cx, |view, cx| {
                            view.status = next;
                            cx.notify();
                        })
                        .is_err()
                {
                    break;
                }
            }
        });
        Self {
            endpoint,
            status: Snapshot {
                status: "Connecting…".into(),
                devices: None,
            },
            _refresh: refresh,
        }
    }
}
impl Render for Dashboard {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .bg(rgb(0x101820))
            .text_color(rgb(0xe8eef2))
            .p_8()
            .flex()
            .flex_col()
            .gap_4()
            .child(div().text_3xl().child("RustCtrl"))
            .child("Foundation · Server connection")
            .child(format!("Server: {}", self.endpoint))
            .child(self.status.status.clone())
            .child(
                self.status
                    .devices
                    .map(|count| format!("Registered devices: {count}"))
                    .unwrap_or_else(|| {
                        "Inventory is unavailable until the server responds.".into()
                    }),
            )
            .child("Remote control and management features will be added through feature tickets.")
    }
}

pub fn open(config: ControllerConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty())),
        "A graphical session is required. Run the Controller on an X11 or Wayland desktop; use the check command for headless diagnostics."
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let snapshot = Arc::new(Mutex::new(Snapshot {
        status: "Connecting…".into(),
        devices: None,
    }));
    let worker_snapshot = snapshot.clone();
    let endpoint = config.server.endpoint.clone();
    runtime.spawn(async move {
        loop {
            let result: Result<_> = async {
                Ok(rustctrl_network::connect(&config.server)
                    .await?
                    .get_health(HealthRequest {})
                    .await?
                    .into_inner())
            }
            .await;
            let update = match result {
                Ok(health) => Snapshot {
                    status: format!("Connected over mutual TLS · Server {}", health.version),
                    devices: Some(health.registered_devices),
                },
                Err(error) => {
                    tracing::warn!(%error, "server health check failed");
                    Snapshot {
                        status:
                            "Server unavailable. Check the server address and TLS configuration."
                                .into(),
                        devices: None,
                    }
                }
            };
            if let Ok(mut snapshot) = worker_snapshot.lock() {
                *snapshot = update;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    gpui_platform::application().run(move |cx: &mut App| {
        cx.open_window(WindowOptions::default(), |_, cx| {
            cx.new(|cx| Dashboard::new(endpoint, snapshot, cx))
        })
        .expect("open RustCtrl window");
        cx.activate(true);
    });
    runtime.shutdown_background();
    Ok(())
}
