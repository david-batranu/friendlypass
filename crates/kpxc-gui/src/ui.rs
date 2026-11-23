//! The BUI (Blender UI) rendering layer.
//!
//! Everything the user sees is built here with `blenderui` elements: the
//! unlock screen, the toolbar, group tree, entry table, details panel and
//! the modal dialogs. Elements carry stable ids so the headless tests can
//! find and click them.

use blenderui::prelude::*;
use crate::state::{
    BuiApp, Details, EntryDraft, GeneratorDraft, Modal, NewDbDraft,
};

const PANEL: u32 = 0x2b2b2b;
const PANEL_DARK: u32 = 0x232323;
const SELECTED: u32 = 0x4772b3;
const MUTED: u32 = 0xa0a0a0;
const ERROR: u32 = 0xff7b72;
const ROW_H: f32 = 24.0;

impl Render for BuiApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let screen = if self.db.is_some() {
            self.main_view(cx)
        } else {
            self.unlock_view(cx)
        };
        html().styled().child(
            body().m_0().css("height", "100vh").overflow_hidden().child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .h_full()
                    .bg(rgb(PANEL_DARK))
                    .child(screen)
                    .child(self.modal_layer(cx)),
            ),
        )
    }
}

impl BuiApp {
    // -----------------------------------------------------------------------
    // shared widgets
    // -----------------------------------------------------------------------

    fn unlock_view(&mut self, cx: &mut Context<Self>) -> Div {
        let mut card = div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .p(px(20.0))
            .w(px(720.0))
            .bg(rgb(PANEL))
            .rounded_md();

        card = card.child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(
                    div()
                        .text_size(px(24.0))
                        .font_weight(FontWeight::BOLD)
                        .child("KeePassXC-RS"),
                )
                .child(
                    div()
                        .text_color(rgb(MUTED))
                        .child("KeePassXC core in Rust · BUI (Blender UI)"),
                ),
        );

        // Recently opened databases.
        if !self.prefs.recent.is_empty() {
            let mut recent = div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .p(px(8.0))
                .bg(rgb(PANEL_DARK))
                .rounded_sm();
            recent = recent.child(
                div()
                    .text_color(rgb(MUTED))
                    .text_size(px(12.0))
                    .child("Recent databases"),
            );
            for (i, path) in self.prefs.recent.clone().into_iter().enumerate() {
                let p = std::path::PathBuf::from(&path);
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let missing = !p.exists();
                let label = if missing {
                    format!("{name}  (missing)")
                } else {
                    name
                };
                let fill = path.clone();
                recent = recent.child(
                    div()
                        .id(format!("recent-{i}"))
                        .px(px(6.0))
                        .py(px(3.0))
                        .rounded_sm()
                        .when(missing, |d| d.text_color(rgb(MUTED)))
                        .hover(|s| s.bg(rgb(0x3a3a3a)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.db_path = fill.clone();
                            this.unlock_error.clear();
                            cx.notify();
                        }))
                        .child(label)
                        .child(
                            div()
                                .text_size(px(11.0))
                                .text_color(rgb(MUTED))
                                .truncate()
                                .child(path),
                        ),
                );
            }
            card = card.child(recent);
        }

        card = card
            .child(field_row(
                "Database file:",
                input()
                    .id("db-path")
                    .value(self.db_path.clone())
                    .w(px(470.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        this.db_path = e.value.clone();
                        cx.notify();
                    })),
            ))
            .child(
                div().flex().gap(px(6.0)).pl(px(150.0)).child(
                    button().id("browse-db").child("Browse…").on_click(cx.listener(
                        |this, _, _, cx| {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("KeePass database", &["kdbx", "kdb"])
                                .pick_file()
                            {
                                this.db_path = p.display().to_string();
                                cx.notify();
                            }
                        },
                    )),
                ),
            )
            .child(field_row(
                "Password:",
                input()
                    .id("password")
                    .input_type("password")
                    .value(self.password.clone())
                    .w(px(470.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        this.password = e.value.clone();
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Key file (optional):",
                div().flex().gap(px(6.0)).child(
                    input()
                        .id("key-file")
                        .value(self.key_file.clone())
                        .w(px(360.0))
                        .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                            this.key_file = e.value.clone();
                            cx.notify();
                        })),
                ),
            ))
            .child(field_row(
                "Challenge-response (hex):",
                input()
                    .id("cr-secret")
                    .value(self.challenge_response.clone())
                    .w(px(470.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        this.challenge_response = e.value.clone();
                        cx.notify();
                    })),
            ));

        if !self.unlock_error.is_empty() {
            card = card.child(
                div()
                    .text_color(rgb(ERROR))
                    .w_full()
                    .child(self.unlock_error.clone()),
            );
        }

        card = card.child(
            div()
                .flex()
                .gap(px(8.0))
                .pt(px(4.0))
                .child(button().id("unlock").child("Unlock").on_click(cx.listener(
                    |this, _, _, cx| {
                        this.try_unlock();
                        cx.notify();
                    },
                )))
                .child(
                    button()
                        .id("new-database")
                        .child("Create new database…")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.modal = Some(Modal::NewDb(NewDbDraft::default()));
                            cx.notify();
                        })),
                ),
        );

        div()
            .flex()
            .flex_1()
            .items_center()
            .justify_center()
            .p(px(24.0))
            .child(card)
    }

    fn main_view(&mut self, cx: &mut Context<Self>) -> Div {
        let db_name = std::path::Path::new(&self.db_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "database".into());

        // -- toolbar ---------------------------------------------------------
        let mut toolbar = div()
            .flex()
            .items_center()
            .gap(px(6.0))
            .px(px(8.0))
            .py(px(4.0))
            .w_full()
            .bg(rgb(PANEL));
        toolbar = toolbar
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .child(format!("{db_name}{}", if self.dirty { " *" } else { "" })),
            )
            .child(div().w(px(1.0)).h(px(20.0)).bg(rgb(0x555555)))
            .child(label().child("Search:"))
            .child(
                input()
                    .id("search")
                    .attr("live", "")
                    .value(self.search.clone())
                    .w(px(220.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        this.search = e.value.clone();
                        cx.notify();
                    })),
            )
            .when(!self.search.is_empty(), |d| {
                d.child(button().id("clear-search").child("Clear").on_click(
                    cx.listener(|this, _, _, cx| {
                        this.search.clear();
                        cx.notify();
                    }),
                ))
            })
            .child(div().w(px(1.0)).h(px(20.0)).bg(rgb(0x555555)))
            .child(button().id("new-entry").child("New Entry").on_click(
                cx.listener(|this, _, _, cx| {
                    this.new_entry();
                    cx.notify();
                }),
            ))
            .child(button().id("new-group").child("New Group").on_click(
                cx.listener(|this, _, _, cx| {
                    if let Some(db) = this.db.as_ref() {
                        let parent = this.selected_group.unwrap_or_else(|| db.root().id());
                        this.modal = Some(Modal::GroupNew {
                            parent,
                            name: String::new(),
                        });
                        cx.notify();
                    }
                }),
            ))
            .child(button().id("generator").child("Generator…").on_click(
                cx.listener(|this, _, _, cx| {
                    let mut draft = GeneratorDraft::default();
                    draft.generate();
                    this.modal = Some(Modal::Generator(draft));
                    cx.notify();
                }),
            ))
            .child(button().id("columns").child("Columns…").on_click(
                cx.listener(|this, _, _, cx| {
                    this.modal = Some(Modal::Columns);
                    cx.notify();
                }),
            ))
            .child(button().id("db-info").child("Info").on_click(
                cx.listener(|this, _, _, cx| {
                    this.modal = Some(Modal::DbInfo);
                    cx.notify();
                }),
            ))
            .child(
                label().child(
                    input()
                        .id("show-passwords")
                        .input_type("checkbox")
                        .checked(self.show_passwords)
                        .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                            this.show_passwords = e.checked;
                            cx.notify();
                        })),
                ),
            )
            .child(div().text_color(rgb(MUTED)).child("Show passwords"))
            .child(div().flex_1())
            .child(button().id("save").child("Save").on_click(cx.listener(
                |this, _, _, cx| {
                    this.save();
                    cx.notify();
                },
            )))
            .child(button().id("lock").child("Lock").on_click(cx.listener(
                |this, _, _, cx| {
                    this.lock();
                    cx.notify();
                },
            )));

        // -- sidebar ---------------------------------------------------------
        let mut sidebar = div()
            .flex()
            .flex_col()
            .gap(px(1.0))
            .w(px(230.0))
            .h_full()
            .p(px(6.0))
            .overflow_y_scroll()
            .bg(rgb(PANEL));
        sidebar = sidebar.child(
            div()
                .text_color(rgb(MUTED))
                .text_size(px(12.0))
                .pb(px(2.0))
                .child("Groups"),
        );
        let all_selected = self.selected_group.is_none();
        sidebar = sidebar.child(
            div()
                .id("group-all")
                .px(px(6.0))
                .h(px(22.0))
                .flex()
                .items_center()
                .rounded_sm()
                .when(all_selected, |d| d.bg(rgb(SELECTED)))
                .hover(|s| s.bg(rgb(0x3a3a3a)))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.selected_group = None;
                    cx.notify();
                }))
                .child("All entries"),
        );
        for node in self.group_tree() {
            let selected = self.selected_group == Some(node.id);
            let gid = node.id;
            sidebar = sidebar.child(
                div()
                    .id(format!("group-{}", gid))
                    .px(px(6.0))
                    .pl(px(6.0 + node.depth as f32 * 14.0))
                    .h(px(22.0))
                    .flex()
                    .items_center()
                    .justify_between()
                    .rounded_sm()
                    .when(selected, |d| d.bg(rgb(SELECTED)))
                    .hover(|s| s.bg(rgb(0x3a3a3a)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected_group = Some(gid);
                        this.selected_entry = None;
                        cx.notify();
                    }))
                    .child(div().truncate().child(node.name.clone()))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(MUTED))
                            .child(format!("{}", node.entries)),
                    ),
            );
        }

        // -- entry table -----------------------------------------------------
        let columns = self.columns();
        let rows = self.rows();
        let searching = !self.search.trim().is_empty();
        let mut header = div()
            .flex()
            .items_center()
            .h(px(26.0))
            .w_full()
            .bg(rgb(PANEL))
            .text_size(px(12.0));
        if searching {
            header = header.child(
                div()
                    .id("hdr-Group")
                    .px(px(6.0))
                    .w(px(170.0))
                    .font_weight(FontWeight::BOLD)
                    .child("Group"),
            );
        }
        for c in &columns {
            let id = c.id;
            let label = c.id.label();
            let mark = if self.sort_column == id {
                if self.sort_desc {
                    " ▼"
                } else {
                    " ▲"
                }
            } else {
                ""
            };
            header = header.child(
                div()
                    .id(format!("hdr-{}", label))
                    .px(px(6.0))
                    .w(px(c.width))
                    .font_weight(FontWeight::BOLD)
                    .truncate()
                    .hover(|s| s.bg(rgb(0x3a3a3a)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if this.sort_column == id {
                            this.sort_desc = !this.sort_desc;
                        } else {
                            this.sort_column = id;
                            this.sort_desc = false;
                        }
                        cx.notify();
                    }))
                    .child(format!("{label}{mark}")),
            );
        }

        let mut list = div().flex().flex_col().w_full().flex_1().overflow_y_scroll();
        for (i, row) in rows.iter().enumerate() {
            let selected = self.selected_entry == Some(row.id);
            let entry_id = row.id;
            let group_id = row.group;
            let mut cells = div()
                .id(format!("entry-{}", entry_id))
                .flex()
                .items_center()
                .h(px(ROW_H))
                .w_full()
                .text_size(px(13.0))
                .when(i % 2 == 1, |d| d.bg(rgb(0x272727)))
                .when(selected, |d| d.bg(rgb(SELECTED)))
                .hover(|s| s.bg(rgb(0x3a3a3a)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.selected_entry = Some(entry_id);
                    this.selected_group = Some(group_id);
                    cx.notify();
                }));
            if searching {
                cells = cells.child(
                    div()
                        .px(px(6.0))
                        .w(px(170.0))
                        .truncate()
                        .text_color(rgb(MUTED))
                        .child(row.group_path.clone()),
                );
            }
            for c in &columns {
                let text = match c.id {
                    kpxc_gui_config::ColumnId::Title => &row.title,
                    kpxc_gui_config::ColumnId::UserName => &row.username,
                    kpxc_gui_config::ColumnId::Password => &row.password,
                    kpxc_gui_config::ColumnId::Url => &row.url,
                    kpxc_gui_config::ColumnId::Notes => &row.notes,
                    kpxc_gui_config::ColumnId::Tags => &row.tags,
                };
                let shown = if c.id == kpxc_gui_config::ColumnId::Password && !self.show_passwords {
                    if text.is_empty() {
                        String::new()
                    } else {
                        "••••••••".to_string()
                    }
                } else {
                    text.clone()
                };
                cells = cells.child(
                    div()
                        .px(px(6.0))
                        .w(px(c.width))
                        .truncate()
                        .child(shown),
                );
            }
            list = list.child(cells);
        }
        if rows.is_empty() {
            list = list.child(
                div()
                    .p(px(16.0))
                    .text_color(rgb(MUTED))
                    .child(if searching {
                        "No entries match the search."
                    } else {
                        "No entries in this group. Use “New Entry” to add one."
                    }),
            );
        }

        let center = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w(px(0.0))
            .h_full()
            .child(header)
            .child(list);

        // -- details ---------------------------------------------------------
        let details = self.details();
        let mut details_panel = div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .w(px(360.0))
            .h_full()
            .p(px(8.0))
            .overflow_y_scroll()
            .bg(rgb(PANEL));
        details_panel = match &details {
            Some(d) => details_panel.child(self.details_content(d, cx)),
            None => details_panel.child(
                div()
                    .text_color(rgb(MUTED))
                    .child("Select an entry to see its details."),
            ),
        };

        // -- status bar ------------------------------------------------------
        let status = div()
            .flex()
            .items_center()
            .justify_between()
            .px(px(8.0))
            .h(px(24.0))
            .w_full()
            .text_size(px(12.0))
            .bg(rgb(PANEL))
            .child(
                div()
                    .text_color(rgb(MUTED))
                    .truncate()
                    .child(self.status.clone()),
            )
            .child(
                div()
                    .text_color(rgb(MUTED))
                    .child(format!("{} entries", rows.len())),
            );

        div()
            .flex()
            .flex_col()
            .h_full()
            .w_full()
            .child(toolbar)
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h(px(0.0))
                    .w_full()
                    .child(sidebar)
                    .child(center)
                    .child(details_panel),
            )
            .child(status)
    }

    fn details_content(&mut self, details: &Details, cx: &mut Context<Self>) -> Div {
        let mut panel = div().flex().flex_col().gap(px(3.0)).w_full();
        panel = panel
            .child(
                div()
                    .id("details-title")
                    .text_size(px(18.0))
                    .font_weight(FontWeight::BOLD)
                    .child(details.title.clone()),
            )
            .child(detail_row(
                "UserName",
                &details.username,
                "copy-username",
                cx,
            ))
            .child(detail_row(
                "Password",
                if self.show_passwords {
                    &details.password
                } else {
                    "••••••••"
                },
                "copy-password",
                cx,
            ))
            .child(
                div().flex().gap(px(6.0)).child(
                    button()
                        .id("toggle-password")
                        .child(if self.show_passwords { "Hide" } else { "Show" })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.show_passwords = !this.show_passwords;
                            cx.notify();
                        })),
                ),
            )
            .child(detail_row("URL", &details.url, "copy-url", cx));
        if let Some((code, valid_for)) = &details.totp {
            panel = panel.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().w(px(90.0)).text_color(rgb(MUTED)).child("TOTP"))
                    .child(
                        div()
                            .id("totp-code")
                            .text_size(px(17.0))
                            .font_weight(FontWeight::BOLD)
                            .child(code.clone()),
                    )
                    .child(
                        div()
                            .text_color(rgb(MUTED))
                            .text_size(px(11.0))
                            .child(format!("{valid_for}s")),
                    )
                    .child(
                        button()
                            .id("copy-totp")
                            .child("Copy")
                            .on_click(cx.listener(|this, _, window, cx| {
                                let Some(d) = this.details() else { return };
                                if let Some((code, _)) = d.totp {
                                    window.write_clipboard(&code);
                                    this.status = "Copied TOTP to clipboard".into();
                                    cx.notify();
                                }
                            })),
                    ),
            );
        }
        if !details.tags.is_empty() {
            panel = panel.child(detail_row("Tags", &details.tags, "copy-tags", cx));
        }
        if !details.attributes.is_empty() {
            panel = panel.child(
                div()
                    .text_color(rgb(MUTED))
                    .pt(px(4.0))
                    .child("Custom attributes"),
            );
            for (key, value, _protected) in &details.attributes {
                let key = key.clone();
                let val = value.clone();
                panel = panel.child(
                    div()
                        .flex()
                        .gap(px(4.0))
                        .items_center()
                        .child(div().w(px(100.0)).truncate().child(key.clone()))
                        .child(div().flex_1().truncate().child(value.clone()))
                        .child(
                            button()
                                .id(format!("copy-attr-{key}"))
                                .child("Copy")
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    window.write_clipboard(&val);
                                    this.status = format!("Copied {key} to clipboard");
                                    cx.notify();
                                })),
                        ),
                );
            }
        }
        panel = panel
            .child(
                div()
                    .text_color(rgb(MUTED))
                    .pt(px(4.0))
                    .child("Notes"),
            )
            .child(div().child(details.notes.clone()))
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .pt(px(8.0))
                    .child(button().id("edit-entry").child("Edit").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.edit_selected();
                            cx.notify();
                        }),
                    ))
                    .child(button().id("delete-entry").child("Delete").on_click(
                        cx.listener(|this, _, _, cx| {
                            let Some(id) = this.selected_entry else { return };
                            this.modal = Some(Modal::ConfirmDeleteEntry(id));
                            cx.notify();
                        }),
                    )),
            );
        panel
    }

    // -----------------------------------------------------------------------
    // modals
    // -----------------------------------------------------------------------

    fn modal_layer(&mut self, cx: &mut Context<Self>) -> Div {
        let Some(modal) = self.modal.clone() else {
            return div();
        };
        let mut panel = div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .p(px(16.0))
            .w(px(640.0))
            .max_h(px(700.0))
            .overflow_y_scroll()
            .bg(rgb(PANEL))
            .rounded_md()
            .text_size(px(13.0));

        panel = match modal {
            Modal::Entry(d) => self.entry_modal(d, cx),
            Modal::GroupNew { parent, name } => {
                let mut name = name;
                panel = panel
                    .child(
                        div()
                            .text_size(px(18.0))
                            .font_weight(FontWeight::BOLD)
                            .child("New Group"),
                    )
                    .child(field_row(
                        "Name:",
                        input()
                            .id("group-name")
                            .value(name.clone())
                            .w(px(420.0))
                            .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                                if let Some(Modal::GroupNew { name, .. }) = this.modal.as_mut() {
                                    *name = e.value.clone();
                                }
                                cx.notify();
                            })),
                    ))
                    .child(
                        div()
                            .flex()
                            .gap(px(6.0))
                            .child(button().id("group-create").child("Create").on_click(
                                cx.listener(move |this, _, _, cx| {
                                    let name = match this.modal.clone() {
                                        Some(Modal::GroupNew { name, .. }) => name,
                                        _ => String::new(),
                                    };
                                    this.add_group(parent, &name);
                                    cx.notify();
                                }),
                            ))
                            .child(button().id("group-cancel").child("Cancel").on_click(
                                cx.listener(|this, _, _, cx| {
                                    this.modal = None;
                                    cx.notify();
                                }),
                            )),
                    );
                name.clear();
                panel
            }
            Modal::NewDb(d) => self.new_db_modal(d, cx),
            Modal::Generator(d) => self.generator_modal(d, cx),
            Modal::Columns => self.columns_modal(cx),
            Modal::DbInfo => {
                let (entries, groups, version) = match self.db.as_ref() {
                    Some(db) => (
                        db.num_entries(),
                        db.num_groups(),
                        format!("{:?}", db.config.version),
                    ),
                    None => (0, 0, "-".into()),
                };
                panel
                    .child(
                        div()
                            .text_size(px(18.0))
                            .font_weight(FontWeight::BOLD)
                            .child("Database Info"),
                    )
                    .child(format!("File: {}", self.db_path))
                    .child(format!("Version: {version}"))
                    .child(format!("Entries: {entries}"))
                    .child(format!("Groups: {groups}"))
                    .child(button().id("db-info-close").child("Close").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.modal = None;
                            cx.notify();
                        }),
                    ))
            }
            Modal::ConfirmDeleteEntry(id) => panel
                .child(
                    div()
                        .text_size(px(18.0))
                        .font_weight(FontWeight::BOLD)
                        .child("Delete entry?"),
                )
                .child("The entry will be moved to the Recycle Bin (or deleted permanently when the bin is disabled).")
                .child(
                    div()
                        .flex()
                        .gap(px(6.0))
                        .child(button().id("confirm-delete").child("Delete").on_click(
                            cx.listener(move |this, _, _, cx| {
                                this.delete_entry(id);
                                cx.notify();
                            }),
                        ))
                        .child(button().id("cancel-delete").child("Cancel").on_click(
                            cx.listener(|this, _, _, cx| {
                                this.modal = None;
                                cx.notify();
                            }),
                        )),
                ),
            Modal::Message(text) => panel
                .child(div().child(text))
                .child(button().id("message-close").child("Close").on_click(
                    cx.listener(|this, _, _, cx| {
                        this.modal = None;
                        cx.notify();
                    }),
                )),
        };

        div()
            .style(
                "position: fixed; left: 0; top: 0; width: 100%; height: 100%; z-index: 100;",
            )
            .bg(rgba(0x000000aa))
            .flex()
            .items_center()
            .justify_center()
            .child(panel)
    }

    fn entry_modal(&mut self, draft: EntryDraft, cx: &mut Context<Self>) -> Div {
        let d = draft.clone();
        let editing = d.id.is_some();
        let mut panel = div().flex().flex_col().gap(px(6.0));
        panel = panel
            .child(
                div()
                    .text_size(px(18.0))
                    .font_weight(FontWeight::BOLD)
                    .child(if editing { "Edit Entry" } else { "New Entry" }),
            )
            .child(field_row(
                "Title:",
                input()
                    .id("entry-title")
                    .value(d.title.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.title = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "UserName:",
                input()
                    .id("entry-username")
                    .value(d.username.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.username = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Password:",
                div().flex().gap(px(4.0)).items_center().child(
                    input()
                        .id("entry-password")
                        .input_type(if d.show_password { "text" } else { "password" })
                        .value(d.password.clone())
                        .w(px(330.0))
                        .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                            if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                                d.password = e.value.clone();
                            }
                            cx.notify();
                        })),
                ),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .pl(px(150.0))
                    .child(button().id("entry-show").child(if d.show_password {
                        "Hide"
                    } else {
                        "Show"
                    }).on_click(cx.listener(|this, _, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.show_password = !d.show_password;
                        }
                        cx.notify();
                    })))
                    .child(
                        button()
                            .id("entry-generate")
                            .child("Generate")
                            .on_click(cx.listener(|this, _, _, cx| {
                                let pw = kpxc::commands::generate_password_opts(
                                    24, true, true, true, true,
                                );
                                if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                                    d.password = pw;
                                }
                                cx.notify();
                            })),
                    ),
            )
            .child(field_row(
                "URL:",
                input()
                    .id("entry-url")
                    .value(d.url.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.url = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Tags:",
                input()
                    .id("entry-tags")
                    .value(d.tags.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.tags = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Notes:",
                textarea()
                    .id("entry-notes")
                    .value(d.notes.clone())
                    .w(px(460.0))
                    .h(px(100.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Entry(d)) = this.modal.as_mut() {
                            d.notes = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .child(button().id("entry-save").child("Save").on_click(
                        cx.listener(|this, _, _, cx| {
                            if let Some(Modal::Entry(d)) = this.modal.clone() {
                                this.apply_entry(d);
                            }
                            cx.notify();
                        }),
                    ))
                    .child(button().id("entry-cancel").child("Cancel").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.modal = None;
                            cx.notify();
                        }),
                    )),
            );
        panel
    }

    fn new_db_modal(&mut self, draft: NewDbDraft, cx: &mut Context<Self>) -> Div {
        let d = draft.clone();
        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(18.0))
                    .font_weight(FontWeight::BOLD)
                    .child("Create New Database"),
            )
            .child(field_row(
                "File path:",
                input()
                    .id("newdb-path")
                    .value(d.path.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                            d.path = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Database name:",
                input()
                    .id("newdb-name")
                    .value(d.name.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                            d.name = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Password:",
                input()
                    .id("newdb-password")
                    .input_type("password")
                    .value(d.password.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                            d.password = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .child(field_row(
                "Repeat password:",
                input()
                    .id("newdb-repeat")
                    .input_type("password")
                    .value(d.password_repeat.clone())
                    .w(px(460.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                            d.password_repeat = e.value.clone();
                        }
                        cx.notify();
                    })),
            ))
            .when(!d.error.is_empty(), |p| {
                p.child(div().text_color(rgb(ERROR)).child(d.error.clone()))
            })
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .child(button().id("newdb-create").child("Create").on_click(
                        cx.listener(|this, _, _, cx| {
                            let Some(Modal::NewDb(d)) = this.modal.clone() else { return };
                            if let Err(e) = d.validate() {
                                if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                                    d.error = e;
                                }
                                cx.notify();
                                return;
                            }
                            match d.create() {
                                Ok((db, key)) => {
                                    this.db = Some(db);
                                    this.db_key = Some(key);
                                    this.db_path = d.path.clone();
                                    this.dirty = false;
                                    this.selected_group = None;
                                    this.selected_entry = None;
                                    this.modal = None;
                                    this.status = format!("Created {}", d.path);
                                    let path = d.path.clone();
                                    this.record_recent(&path);
                                }
                                Err(e) => {
                                    if let Some(Modal::NewDb(d)) = this.modal.as_mut() {
                                        d.error = e;
                                    }
                                }
                            }
                            cx.notify();
                        }),
                    ))
                    .child(button().id("newdb-cancel").child("Cancel").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.modal = None;
                            cx.notify();
                        }),
                    )),
            )
    }

    fn generator_modal(&mut self, draft: GeneratorDraft, cx: &mut Context<Self>) -> Div {
        let d = draft.clone();
        let mut panel = div().flex().flex_col().gap(px(6.0));
        panel = panel
            .child(
                div()
                    .text_size(px(18.0))
                    .font_weight(FontWeight::BOLD)
                    .child("Password Generator"),
            )
            .child(
                div()
                    .id("gen-value")
                    .text_size(px(18.0))
                    .truncate()
                    .child(d.value.clone()),
            )
            .child(field_row(
                "Length:",
                input()
                    .id("gen-length")
                    .input_type("number")
                    .min(4.0)
                    .max(128.0)
                    .value(d.length.to_string())
                    .w(px(100.0))
                    .on_change(cx.listener(|this, e: &ChangeEvent, _, cx| {
                        if let Some(Modal::Generator(d)) = this.modal.as_mut() {
                            if let Ok(n) = e.value.parse::<usize>() {
                                d.length = n.clamp(4, 128);
                            }
                        }
                        cx.notify();
                    })),
            ));
        for (key, text) in [
            ("gen-upper", "Uppercase"),
            ("gen-lower", "Lowercase"),
            ("gen-digits", "Digits"),
            ("gen-symbols", "Symbols"),
        ] {
            let checked = match key {
                "gen-upper" => d.uppercase,
                "gen-lower" => d.lowercase,
                "gen-digits" => d.digits,
                _ => d.symbols,
            };
            panel = panel.child(
                label().child(
                    input()
                        .id(key)
                        .input_type("checkbox")
                        .checked(checked)
                        .on_change(cx.listener(move |this, e: &ChangeEvent, _, cx| {
                            if let Some(Modal::Generator(d)) = this.modal.as_mut() {
                                match key {
                                    "gen-upper" => d.uppercase = e.checked,
                                    "gen-lower" => d.lowercase = e.checked,
                                    "gen-digits" => d.digits = e.checked,
                                    _ => d.symbols = e.checked,
                                }
                            }
                            cx.notify();
                        })),
                )
                .child(format!(" {text}")),
            );
        }
        panel = panel
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .child(button().id("gen-regenerate").child("Regenerate").on_click(
                        cx.listener(|this, _, _, cx| {
                            if let Some(Modal::Generator(d)) = this.modal.as_mut() {
                                d.generate();
                            }
                            cx.notify();
                        }),
                    ))
                    .child(button().id("gen-copy").child("Copy").on_click(
                        cx.listener(|this, _, window, cx| {
                            if let Some(Modal::Generator(d)) = this.modal.as_ref() {
                                window.write_clipboard(&d.value);
                                this.status = "Generated password copied".into();
                            }
                            cx.notify();
                        }),
                    ))
                    .child(button().id("gen-use").child("Use for entry").on_click(
                        cx.listener(|this, _, _, cx| {
                            let Some(Modal::Generator(d)) = this.modal.clone() else { return };
                            let group = this
                                .selected_group
                                .unwrap_or_else(|| this.db.as_ref().unwrap().root().id());
                            let mut draft = EntryDraft::new(group);
                            draft.password = d.value.clone();
                            this.modal = Some(Modal::Entry(draft));
                            cx.notify();
                        }),
                    ))
                    .child(button().id("gen-close").child("Close").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.modal = None;
                            cx.notify();
                        }),
                    )),
            );
        panel
    }

    fn columns_modal(&mut self, cx: &mut Context<Self>) -> Div {
        let cols = self.prefs.columns.clone();
        let mut panel = div().flex().flex_col().gap(px(4.0));
        panel = panel.child(
            div()
                .text_size(px(18.0))
                .font_weight(FontWeight::BOLD)
                .child("Columns"),
        );
        for c in cols {
            let id = c.id;
            panel = panel.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        label().child(
                            input()
                                .id(format!("col-{}", id.label()))
                                .input_type("checkbox")
                                .checked(c.visible)
                                .on_change(cx.listener(move |this, e: &ChangeEvent, _, cx| {
                                    this.set_column_visible(id, e.checked);
                                    cx.notify();
                                })),
                        )
                        .child(format!(" {} column", id.label())),
                    )
                    .child(button().id(format!("col-up-{}", id.label())).child("Up").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.move_column(id, true);
                            cx.notify();
                        }),
                    ))
                    .child(button().id(format!("col-down-{}", id.label())).child("Down").on_click(
                        cx.listener(move |this, _, _, cx| {
                            this.move_column(id, false);
                            cx.notify();
                        }),
                    )),
            );
        }
        panel = panel
            .child(
                div()
                    .flex()
                    .gap(px(6.0))
                    .child(button().id("columns-reset").child("Reset to defaults").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.prefs.columns =
                                kpxc_gui_config::Preferences::default().columns;
                            this.save_preferences();
                            cx.notify();
                        }),
                    ))
                    .child(button().id("columns-close").child("Close").on_click(
                        cx.listener(|this, _, _, cx| {
                            this.modal = None;
                            cx.notify();
                        }),
                    )),
            );
        panel
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn field_row(label: &str, control: impl IntoElement) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(8.0))
        .child(div().w(px(150.0)).text_color(rgb(MUTED)).child(label.to_string()))
        .child(control)
}

fn detail_row(
    label: &str,
    value: &str,
    copy_id: &'static str,
    cx: &mut Context<BuiApp>,
) -> Div {
    let value = value.to_owned();
    let label_owned = label.to_owned();
    div()
        .flex()
        .items_center()
        .gap(px(4.0))
        .child(
            div()
                .w(px(90.0))
                .text_color(rgb(MUTED))
                .child(label.to_owned()),
        )
        .child(div().flex_1().truncate().child(value.clone()))
        .child(
            button()
                .id(copy_id)
                .child("Copy")
                .on_click(cx.listener(move |this, _, window, cx| {
                    window.write_clipboard(&value);
                    this.status = format!("Copied {label_owned} to clipboard");
                    cx.notify();
                })),
        )
}
