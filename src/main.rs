use eframe::egui::{self, Color32, Id, Layout, Modal, RichText, ScrollArea, Style};
use sysinfo::{Pid, ProcessesToUpdate, System};
use egui_file_dialog::FileDialog;
use std::{fs::read_dir, sync::Arc};
use tokio::sync::mpsc;
pub mod processes;
pub mod inject;

pub struct PluginApp {
    pub plugin_dir: String,
    pub plugins: Vec<String>,
    pub load_err: Vec<String>,
    pub selected_plugin: Option<String>,
    pub processes: Vec<(String, sysinfo::Pid)>,
    pub target_pid: Option<Pid>,
    pub system: System,
    pub tx: mpsc::Sender<String>,
    pub rx: mpsc::Receiver<String>,
    pub exported_functions: Vec<ExportInfo>,
    pub selected_function: Option<String>,
    pub process_to_hollow: String,
    file_dialog: FileDialog,
    open_warning_modal: bool,
    first_run: bool,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub virtual_address: usize,
    pub rva: usize,
    pub offset: usize,
}

impl PluginApp {
    fn new() -> Self {
        let default_dir = "D:\\Users\\Owner\\Desktop\\rusty-dll\\target\\release".to_string();
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);
        let mut processes = system
            .processes()
            .iter()
            .map(|(pid, proc_)| (proc_.name().to_string_lossy().into_owned(), *pid))
            .collect::<Vec<_>>();
        processes.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut plugins = vec![];
        if let Ok(entries) = read_dir(&default_dir) {
            plugins = entries
                .filter_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension().map(|e| e == "dll").unwrap_or(false) {
                        path.file_name()?.to_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
        }

        let (tx, rx) = mpsc::channel(32);

        Self {
            plugin_dir: default_dir,
            load_err: Vec::new(),
            selected_plugin: None,
            plugins,
            processes,
            system,
            target_pid: None,
            tx,
            rx,
            exported_functions: Vec::new(),
            selected_function: None,
            process_to_hollow: String::new(),
            file_dialog: FileDialog::new(),
            open_warning_modal: false,
            first_run: true
        }
    }

    fn scan_plugins(&mut self) {
        self.plugins.clear();
        if let Ok(entries) = read_dir(&self.plugin_dir) {
            self.plugins = entries
                .filter_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension().map(|e| e == "dll").unwrap_or(false) {
                        path.file_name()?.to_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
}

impl eframe::App for PluginApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            println!("Err: {msg:?}");
            self.load_err.push(msg);
        }

        if self.first_run {
            self.first_run = false;
            match serde_json::from_str::<Style>(STYLE) {
                Ok(theme) => {
                    let style = Arc::new(theme);
                    ctx.set_style(style);
                }
                Err(e) => println!("Error setting theme: {e:?}")
            };
        }

        egui::TopBottomPanel::top(Id::new("Top Panel Plugin App")).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Plugin Path:             ");
                ui.text_edit_singleline(&mut self.plugin_dir);
                
                ui.add_space(10.);

                if ui.button("Scan").clicked() {
                    self.scan_plugins();
                }
                
                ui.add_space(10.);
                
                if ui.button("Refresh Processes").clicked() {
                    self.scan_processes();
                }
            });

            ui.horizontal(|ui| {
                ui.label("Process to hollow: ");
                ui.text_edit_singleline(&mut self.process_to_hollow);
                ui.add_space(10.);
                if ui.button("...").clicked() {
                    self.file_dialog.pick_file();
                }
                self.file_dialog.update(ctx);

                // Check if the user picked a file.
                if let Some(path) = self.file_dialog.take_picked() {
                    self.process_to_hollow = format!("{}", path.to_string_lossy());
                }

                ui.add_space(27.);

                if ui.button(RichText::new("Hollow Process").color(Color32::LIGHT_RED)).clicked() {
                    if let (Some(function), Some(plugin)) = (&self.selected_function, &self.selected_plugin) {
                        unsafe { 
                            let dummy_process = self.process_to_hollow.as_str();
                            if !dummy_process.is_empty() {
                                let proc_info_res = Self::hollow_process(dummy_process);
                                match proc_info_res {
                                    Ok(proc_info) => {
                                        let pid = proc_info.dwProcessId;
                                        self.target_pid = Some(Pid::from_u32(pid));
                                        self.load_err.push(format!("Selected PID: {}", proc_info.dwProcessId));
                                        self.load_err.push(format!("Hollowed out process: {dummy_process}: proc_info: {proc_info:#?}"));
                                        match Self::inject_hollowed_process(&std::fs::read(format!("{}/{plugin}", self.plugin_dir)).unwrap_or_default(), proc_info.hProcess, function, proc_info.dwProcessId) {
                                            Ok(_) => {
                                                self.load_err.push(format!("Injected {plugin} to PID {}", proc_info.dwProcessId));
                                                let path = format!("{}/{}", self.plugin_dir, plugin);
                                                let tx = self.tx.clone();
                                                match Self::call_exported_fn(plugin.clone(), path, function.clone(), pid, tx.clone()) {
                                                    Ok(_) => { let _ = tx.try_send(format!("Called Exported Fn")); },
                                                    Err(e) => { let _ = tx.try_send(e.to_string()); },
                                                }
                                            },
                                            Err(e) => self.load_err.push(format!("Error injecting {plugin} into PID {}: {e}", proc_info.dwProcessId)),
                                        }
                                    }
                                    Err(e) => self.load_err.push(format!("Error Hollowing out {dummy_process}: {e:?}"))
                                }
                            }
                        };
                    } else {
                        if self.selected_function.is_none() || self.selected_plugin.is_none() {
                            self.open_warning_modal = true;
                        }
                    }
                }
            })
        });

        if self.open_warning_modal {
            let modal = Modal::new(Id::new("Missing selected function modal"))
            .show(ctx, |ui| {
                if self.selected_function.is_none() {
                    ui.label("Missing Selected Function");
                }
                if self.selected_plugin.is_none() {
                    ui.label("Missing Selected Plugin");
                }
                if self.target_pid.is_none() {
                    ui.label("Missing Selected PID");
                }
            });

            if modal.should_close() {
                self.open_warning_modal = false;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |ui| {
                ui[0].vertical_centered(|ui| {
                    ui.heading("Available Processes");
                    ui.separator();
                });
                ScrollArea::vertical()
                .auto_shrink(false)
                .id_salt(Id::new("Processes"))
                .show(&mut ui[0], |ui| {
                    let process = self.processes.clone();
                    for (name, pid) in &process {
                        if ui.button(format!("PID: {} - {}", pid, name)).clicked() {
                            let plugs = self.selected_plugin.clone();
                            let tx = self.tx.clone();
                            let plugin_dir = self.plugin_dir.clone();
                            self.target_pid = Some(*pid);
                            let pid = *pid;
                            if let (Some(plugin), Some(function)) = (plugs, self.selected_function.clone()) {
                                tokio::spawn(async move {
                                    match unsafe { PluginApp::inject_dll(pid, &plugin_dir, &plugin, &function) }.await {
                                        Ok(()) => {
                                            tx.send(format!("Injected into PID {}", pid)).await.ok();
                                        }
                                        Err(e) => {
                                            println!("Error: {e:?}");
                                            tx.send(e).await.ok();
                                        }
                                    }
                                    // match unsafe { PluginApp::hollow_and_inject(pid, plugin_dir, plugin) }.await {
                                    //     Ok(()) => {
                                    //         tx.send(format!("Injected into PID {}", pid)).await.ok();
                                    //     }
                                    //     Err(e) => {
                                    //         println!("Error: {e:?}");
                                    //         tx.send(e).await.ok();
                                    //     }
                                    // }
                                });
                            } else {
                                self.open_warning_modal = true;
                            }
                        }
                    }
                });
                ui[1].vertical_centered(|ui| {
                    ui.heading("Available Plugins");
                    ui.separator();
                    ScrollArea::vertical()
                    .auto_shrink(true)
                    .max_height(200.)
                    .id_salt(Id::new("Available Plugins List"))
                    .show(ui, |ui| {
                        let plugs = self.plugins.clone();
                        for plugin in plugs.iter() {
                            ui.horizontal(|ui| {
                                if ui.radio_value(&mut self.selected_plugin, Some(plugin.clone()), plugin).clicked() {
                                    self.load_err.push(format!("Selected Plugin: {plugin}"));
                                    self.selected_plugin = Some(plugin.clone());
                                    self.list_exports(); // <-- Parse and list exported functions
                                }
                            });
                        }
                    });

                    ui.heading("Available Functions");
                    ui.separator();
                    ScrollArea::both()
                    .auto_shrink(true)
                    .max_height(500.)
                    .id_salt(Id::new("Available Functions List"))
                    .show(ui, |ui| {
                        let exported = self.exported_functions.clone();
                        for export in exported.iter() {
                            ui.horizontal(|ui| {
                                if ui.button(RichText::new("Run").color(Color32::LIGHT_RED)).clicked() {
                                    if let Some(pid) = self.target_pid {
                                        let plugin_name = self.selected_plugin.clone().unwrap();
                                        let path = format!("{}/{}", self.plugin_dir, plugin_name);
                                        let function = export.name.clone();
                                        let tx = self.tx.clone();
                                        let pid = pid.as_u32();
                                        // tokio::spawn(async move {
                                            match unsafe { Self::call_exported_fn(
                                                plugin_name,
                                                path,
                                                function,
                                                pid,
                                                tx.clone()
                                            ) } {
                                                Ok(_) => {
                                                    let _ = tx.try_send(format!("Called Exported Fn"));
                                                },
                                                Err(e) => {
                                                    let _ = tx.try_send(e.to_string());
                                                },
                                            }
                                        // });
                                    } else {
                                        self.open_warning_modal = true;
                                    }
                                }
                                if ui.radio_value(&mut self.selected_function, Some(export.name.clone()), RichText::new(&export.name).color(Color32::LIGHT_GREEN)).clicked() {
                                    self.load_err.push(format!("Selected Function: {}", export.name));
                                }
                                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                                    if export.virtual_address > 0 {
                                        ui.label(format!("{:#X}", export.virtual_address));
                                        ui.colored_label(Color32::LIGHT_GREEN, "Virtual Addr:");
                                    }
                                    
                                    ui.label(format!("{:#X}", export.offset));
                                    ui.colored_label(Color32::LIGHT_BLUE, "Offset:");

                                    ui.label(format!("{:#X}", export.rva));
                                    ui.colored_label(Color32::from_rgb(155, 10, 155), "RVA:");
                                });
                            });
                        }
                    });

                    ui.add_space(50.);

                    ui.heading("Messages");
                    ui.separator();
                    ScrollArea::vertical()
                    .auto_shrink(false)
                    .max_height(200.)
                    .id_salt(Id::new("Error messages"))
                    .show(ui, |ui| {
                        for err in self.load_err.iter() {
                            ui.horizontal(|ui| ui.colored_label(Color32::RED, err.clone()));
                        }
                    });
                });
            });
        });
    }
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    {
        use windows::Win32::System::Threading::GetCurrentProcess;
        use windows::Win32::System::Threading::SetPriorityClass;
        use windows::Win32::System::Threading::ABOVE_NORMAL_PRIORITY_CLASS;
        unsafe {
            let _ = SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
        }
    }

    let app = PluginApp::new();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Plugin App",
        native_options,
        Box::new(|_| Ok(Box::new(app))),
    )
}


const STYLE: &str = r#"{"override_text_style":null,"override_font_id":null,"override_text_valign":"Center","text_styles":{"Small":{"size":10.0,"family":"Proportional"},"Body":{"size":14.0,"family":"Proportional"},"Monospace":{"size":12.0,"family":"Monospace"},"Button":{"size":14.0,"family":"Proportional"},"Heading":{"size":18.0,"family":"Proportional"}},"drag_value_text_style":"Button","wrap":null,"wrap_mode":null,"spacing":{"item_spacing":{"x":3.0,"y":3.0},"window_margin":{"left":12,"right":12,"top":12,"bottom":12},"button_padding":{"x":5.0,"y":3.0},"menu_margin":{"left":12,"right":12,"top":12,"bottom":12},"indent":18.0,"interact_size":{"x":40.0,"y":20.0},"slider_width":100.0,"slider_rail_height":8.0,"combo_width":100.0,"text_edit_width":280.0,"icon_width":14.0,"icon_width_inner":8.0,"icon_spacing":6.0,"default_area_size":{"x":600.0,"y":400.0},"tooltip_width":600.0,"menu_width":400.0,"menu_spacing":2.0,"indent_ends_with_horizontal_line":false,"combo_height":200.0,"scroll":{"floating":true,"bar_width":6.0,"handle_min_length":12.0,"bar_inner_margin":4.0,"bar_outer_margin":0.0,"floating_width":2.0,"floating_allocated_width":0.0,"foreground_color":true,"dormant_background_opacity":0.0,"active_background_opacity":0.4,"interact_background_opacity":0.7,"dormant_handle_opacity":0.0,"active_handle_opacity":0.6,"interact_handle_opacity":1.0}},"interaction":{"interact_radius":5.0,"resize_grab_radius_side":5.0,"resize_grab_radius_corner":10.0,"show_tooltips_only_when_still":true,"tooltip_delay":0.5,"tooltip_grace_time":0.2,"selectable_labels":true,"multi_widget_text_select":true},"visuals":{"dark_mode":true,"text_alpha_from_coverage":"TwoCoverageMinusCoverageSq","override_text_color":[207,216,220,255],"weak_text_alpha":0.6,"weak_text_color":null,"widgets":{"noninteractive":{"bg_fill":[0,0,0,0],"weak_bg_fill":[61,61,61,232],"bg_stroke":{"width":1.0,"color":[71,71,71,247]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[207,216,220,255]},"expansion":0.0},"inactive":{"bg_fill":[58,51,106,0],"weak_bg_fill":[8,8,8,231],"bg_stroke":{"width":1.5,"color":[48,51,73,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[207,216,220,255]},"expansion":0.0},"hovered":{"bg_fill":[37,29,61,97],"weak_bg_fill":[95,62,97,69],"bg_stroke":{"width":1.7,"color":[106,101,155,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.5,"color":[83,87,88,35]},"expansion":2.0},"active":{"bg_fill":[12,12,15,255],"weak_bg_fill":[39,37,54,214],"bg_stroke":{"width":1.0,"color":[12,12,16,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":2.0,"color":[207,216,220,255]},"expansion":1.0},"open":{"bg_fill":[20,22,28,255],"weak_bg_fill":[17,18,22,255],"bg_stroke":{"width":1.8,"color":[42,44,93,165]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[109,109,109,255]},"expansion":0.0}},"selection":{"bg_fill":[23,64,53,27],"stroke":{"width":1.0,"color":[12,12,15,255]}},"hyperlink_color":[135,85,129,255],"faint_bg_color":[17,18,22,255],"extreme_bg_color":[9,12,15,83],"text_edit_bg_color":null,"code_bg_color":[30,31,35,255],"warn_fg_color":[61,185,157,255],"error_fg_color":[255,55,102,255],"window_corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"window_shadow":{"offset":[0,0],"blur":7,"spread":5,"color":[17,17,41,118]},"window_fill":[11,11,15,255],"window_stroke":{"width":1.0,"color":[77,94,120,138]},"window_highlight_topmost":true,"menu_corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"panel_fill":[12,12,15,255],"popup_shadow":{"offset":[0,0],"blur":8,"spread":3,"color":[19,18,18,96]},"resize_corner_size":18.0,"text_cursor":{"stroke":{"width":2.0,"color":[197,192,255,255]},"preview":true,"blink":true,"on_duration":0.5,"off_duration":0.5},"clip_rect_margin":3.0,"button_frame":true,"collapsing_header_frame":true,"indent_has_left_vline":true,"striped":true,"slider_trailing_fill":true,"handle_shape":{"Rect":{"aspect_ratio":0.5}},"interact_cursor":"Crosshair","image_loading_spinners":true,"numeric_color_space":"GammaByte","disabled_alpha":0.5},"animation_time":0.083333336,"debug":{"debug_on_hover":false,"debug_on_hover_with_all_modifiers":false,"hover_shows_next":false,"show_expand_width":false,"show_expand_height":false,"show_resize":false,"show_interactive_widgets":false,"show_widget_hits":false,"show_unaligned":true},"explanation_tooltips":false,"url_in_tooltip":false,"always_scroll_the_only_direction":true,"scroll_animation":{"points_per_second":1000.0,"duration":{"min":0.1,"max":0.3}},"compact_menu_style":true}"#;