use super::{render_dialog_error, render_dialog_field};
use crate::gui::ControllerApp;
use crate::gui::state::{ModalInputs, Overlay, ScreenState};
use crate::theme::Theme;
use gpui::assets::IconName;
use gpui::base::StyledExt as _;
use gpui::component::alert::Alert;
use gpui::component::button::{Button, ButtonVariants as _};
use gpui::component::dialog::{
    Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
};
use gpui::component::input::Input;
use gpui::component::tag::Tag;
use gpui::component::{Disableable as _, Icon, Sizable as _};
use gpui::{
    App, ClipboardItem, Entity, InteractiveElement as _, ParentElement as _, Styled as _, px, rgb,
};

pub(crate) fn render_create_account_dialog(
    overlay: &Overlay,
    inputs: &ModalInputs,
    theme: &Theme,
    app: Entity<ControllerApp>,
    cx: &mut App,
) -> Dialog {
    let Overlay::CreateStaffAccount {
        role,
        error,
        in_flight,
        created,
        ..
    } = overlay
    else {
        return Dialog::new(cx);
    };

    let in_flight = *in_flight;
    let error = error.as_ref();
    let created = created.as_ref();

    let ModalInputs::CreateStaffAccount {
        username,
        temporary_password,
    } = inputs
    else {
        return Dialog::new(cx);
    };

    let app_close = app.clone();
    let app_cancel = app.clone();
    let app_submit = app.clone();
    let app_done = app.clone();
    let app_copy = app.clone();
    let app_gen = app.clone();
    let temp_pass_entity = temporary_password.clone();

    let mut dialog = Dialog::new(cx)
        .w(px(520.0))
        .centered()
        .close_button(!in_flight)
        .keyboard(!in_flight)
        .overlay_closable(!in_flight)
        .on_close(move |_, _, cx| {
            app_close.update(cx, |this, cx| {
                this.close_overlay(cx);
            });
        });

    if let Some(info) = created {
        let creds_text = format!(
            "RustCtrl Staff Account Credentials\n\
             Username: {}\n\
             Temporary Password: {}\n\
             Role: {}\n\n\
             Note: You are required to replace this temporary password upon your initial sign-in.",
            info.username, info.temporary_password, info.role
        );
        let creds_for_copy = creds_text.clone();
        let pass_for_copy = info.temporary_password.clone();
        let role_is_admin = info.role == "admin";

        dialog = dialog
            .child(
                DialogHeader::new()
                    .child(DialogTitle::new().child("Staff Account Created"))
                    .child(DialogDescription::new().child(
                        "Initial administrative credentials have been provisioned successfully.",
                    )),
            )
            .child(
                DialogContent::new()
                    .gap_4()
                    .child(Alert::success(
                        "csa-success-alert",
                        "Account has been provisioned. Provide these initial credentials to the staff member.",
                    ))
                    .child(
                        gpui::div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .p_3p5()
                            .bg(rgb(theme.bg_surface))
                            .rounded_lg()
                            .border_1()
                            .border_color(rgb(theme.border_subtle))
                            .child(
                                gpui::div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        gpui::div()
                                            .text_xs()
                                            .font_weight(gpui::FontWeight::MEDIUM)
                                            .text_color(rgb(theme.text_muted))
                                            .child("USERNAME"),
                                    )
                                    .child(
                                        gpui::div()
                                            .font_semibold()
                                            .text_color(rgb(theme.text_primary))
                                            .child(info.username.clone()),
                                    ),
                            )
                            .child(
                                gpui::div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        gpui::div()
                                            .text_xs()
                                            .font_weight(gpui::FontWeight::MEDIUM)
                                            .text_color(rgb(theme.text_muted))
                                            .child("ASSIGNED ROLE"),
                                    )
                                    .child(if role_is_admin {
                                        Tag::primary().child("Administrator")
                                    } else {
                                        Tag::secondary().child("Operator")
                                    }),
                            )
                            .child(
                                gpui::div()
                                    .flex()
                                    .flex_col()
                                    .gap_1p5()
                                    .child(
                                        gpui::div()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                gpui::div()
                                                    .text_xs()
                                                    .font_weight(gpui::FontWeight::MEDIUM)
                                                    .text_color(rgb(theme.text_muted))
                                                    .child("TEMPORARY PASSWORD"),
                                            )
                                            .child(
                                                Button::new("copy-pass-only-btn")
                                                    .ghost()
                                                    .small()
                                                    .icon(IconName::Copy)
                                                    .label("Copy Password")
                                                    .on_click(move |_, _, cx| {
                                                        cx.write_to_clipboard(ClipboardItem::new_string(
                                                            pass_for_copy.clone(),
                                                        ));
                                                    }),
                                            ),
                                    )
                                    .child(
                                        gpui::div()
                                            .p_2p5()
                                            .bg(rgb(theme.bg_surface_hover))
                                            .rounded_md()
                                            .border_1()
                                            .border_color(rgb(theme.border_subtle))
                                            .child(
                                                gpui::div()
                                                    .text_sm()
                                                    .font_weight(gpui::FontWeight::BOLD)
                                                    .text_color(rgb(theme.accent_primary))
                                                    .child(info.temporary_password.clone()),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        Button::new("csa-copy-all-btn")
                            .primary()
                            .icon(IconName::Copy)
                            .label("Copy All Credentials")
                            .on_click(move |_, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(creds_for_copy.clone()));
                                app_copy.update(cx, |this, _cx| {
                                    this.toast_manager.success(
                                        "Credentials Copied",
                                        "Account credentials copied to clipboard.",
                                    );
                                });
                            }),
                    ),
            )
            .footer(
                DialogFooter::new().child(
                    Button::new("csa-done-btn")
                        .primary()
                        .label("Done")
                        .on_click(move |_, window, cx| {
                            use gpui::component::WindowExt as _;
                            window.close_dialog(cx);
                            app_done.update(cx, |this, cx| {
                                this.close_overlay(cx);
                                if let ScreenState::Connected { session_token, .. } = &this.state {
                                    let tok = session_token.clone();
                                    this.fetch_status(tok, cx);
                                }
                            });
                        }),
                ),
            );
        return dialog;
    }

    // Input Form State
    let is_admin_selected = role == "admin";
    let is_operator_selected = !is_admin_selected;

    let app_op = app.clone();
    let app_admin = app.clone();

    let operator_card = gpui::div()
        .id("role-operator-card")
        .flex()
        .flex_1()
        .flex_col()
        .gap_2()
        .p_3()
        .rounded_lg()
        .border_1()
        .cursor_pointer()
        .border_color(if is_operator_selected {
            rgb(theme.accent_primary)
        } else {
            rgb(theme.border_subtle)
        })
        .bg(if is_operator_selected {
            rgb(theme.bg_surface_hover)
        } else {
            rgb(theme.bg_surface)
        })
        .on_mouse_down(gpui::MouseButton::Left, move |_, _, cx| {
            app_op.update(cx, |this, cx| {
                if let Overlay::CreateStaffAccount { role, .. } = &mut this.overlay {
                    *role = "operator".to_string();
                    cx.notify();
                }
            });
        })
        .child(
            gpui::div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    gpui::div()
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(Icon::new(IconName::UserCheck).text_color(rgb(theme.accent_primary)))
                        .child(
                            gpui::div()
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child("Operator"),
                        ),
                )
                .child(Tag::secondary().child("Standard")),
        )
        .child(
            gpui::div()
                .text_xs()
                .text_color(rgb(theme.text_muted))
                .child("Fleet monitoring and diagnostics. Read-only device inspection."),
        );

    let admin_card = gpui::div()
        .id("role-admin-card")
        .flex()
        .flex_1()
        .flex_col()
        .gap_2()
        .p_3()
        .rounded_lg()
        .border_1()
        .cursor_pointer()
        .border_color(if is_admin_selected {
            rgb(theme.accent_primary)
        } else {
            rgb(theme.border_subtle)
        })
        .bg(if is_admin_selected {
            rgb(theme.bg_surface_hover)
        } else {
            rgb(theme.bg_surface)
        })
        .on_mouse_down(gpui::MouseButton::Left, move |_, _, cx| {
            app_admin.update(cx, |this, cx| {
                if let Overlay::CreateStaffAccount { role, .. } = &mut this.overlay {
                    *role = "admin".to_string();
                    cx.notify();
                }
            });
        })
        .child(
            gpui::div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    gpui::div()
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(
                            Icon::new(IconName::ShieldCheck).text_color(rgb(theme.accent_primary)),
                        )
                        .child(
                            gpui::div()
                                .font_semibold()
                                .text_color(rgb(theme.text_primary))
                                .child("Administrator"),
                        ),
                )
                .child(Tag::primary().child("Elevated")),
        )
        .child(
            gpui::div()
                .text_xs()
                .text_color(rgb(theme.text_muted))
                .child("Full fleet, target, and account administration privileges."),
        );

    let password_header = gpui::div()
        .flex()
        .items_center()
        .justify_between()
        .child(
            gpui::div()
                .text_xs()
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(rgb(theme.text_muted))
                .child("TEMPORARY PASSWORD"),
        )
        .child(
            Button::new("csa-gen-pass-btn")
                .ghost()
                .small()
                .icon(IconName::RotateCw)
                .label("Generate Password")
                .on_click(move |_, window, cx| {
                    let new_pass = rustctrl_core::generate_temporary_password();
                    temp_pass_entity.update(cx, |state, cx| {
                        state.set_value(new_pass.clone(), window, cx);
                    });
                    app_gen.update(cx, |this, cx| {
                        if let Overlay::CreateStaffAccount {
                            temporary_password: pass,
                            ..
                        } = &mut this.overlay
                        {
                            *pass = new_pass;
                            cx.notify();
                        }
                    });
                }),
        );

    dialog
        .child(
            DialogHeader::new()
                .child(DialogTitle::new().child("Create Staff Account"))
                .child(DialogDescription::new().child(
                    "Provision a new staff account with assigned role and temporary credentials.",
                )),
        )
        .child(
            DialogContent::new()
                .gap_4()
                .child(
                    gpui::div()
                        .flex()
                        .flex_col()
                        .gap_1p5()
                        .child(render_dialog_field("Username", Input::new(username), theme))
                        .child(
                            gpui::div()
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child("Allowed characters: a-z, 0-9, dot (.), hyphen (-), underscore (_)"),
                        ),
                )
                .child(
                    gpui::div()
                        .flex()
                        .flex_col()
                        .gap_1p5()
                        .child(
                            gpui::div()
                                .text_xs()
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(rgb(theme.text_muted))
                                .child("ASSIGNED ROLE"),
                        )
                        .child(
                            gpui::div()
                                .flex()
                                .gap_3()
                                .child(operator_card)
                                .child(admin_card),
                        ),
                )
                .child(
                    gpui::div()
                        .flex()
                        .flex_col()
                        .gap_1p5()
                        .child(password_header)
                        .child(Input::new(temporary_password))
                        .child(
                            gpui::div()
                                .text_xs()
                                .text_color(rgb(theme.text_muted))
                                .child("Minimum 8 characters. User must replace temporary password upon sign-in."),
                        ),
                )
                .children(render_dialog_error("csa-error-alert", error)),
        )
        .footer(
            DialogFooter::new()
                .child(
                    Button::new("csa-cancel-btn")
                        .outline()
                        .disabled(in_flight)
                        .label("Cancel")
                        .on_click(move |_, window, cx| {
                            if !in_flight {
                                use gpui::component::WindowExt as _;
                                window.close_dialog(cx);
                                app_cancel.update(cx, |this, cx| this.close_overlay(cx));
                            }
                        }),
                )
                .child(
                    Button::new("csa-submit-btn")
                        .primary()
                        .loading(in_flight)
                        .disabled(in_flight)
                        .label(if in_flight {
                            "Creating..."
                        } else {
                            "Create Staff Account"
                        })
                        .on_click(move |_, _, cx| {
                            if !in_flight {
                                app_submit.update(cx, |this, cx| {
                                    this.submit_create_staff_account(cx);
                                });
                            }
                        }),
                ),
        )
}
