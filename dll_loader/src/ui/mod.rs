use eframe::egui::*;
pub mod tabs;

const STYLE: &str = r#"{"override_text_style":null,"override_font_id":null,"override_text_valign":"Center","text_styles":{"Small":{"size":10.0,"family":"Proportional"},"Body":{"size":14.0,"family":"Proportional"},"Monospace":{"size":12.0,"family":"Monospace"},"Button":{"size":14.0,"family":"Proportional"},"Heading":{"size":18.0,"family":"Proportional"}},"drag_value_text_style":"Button","wrap":null,"wrap_mode":null,"spacing":{"item_spacing":{"x":3.0,"y":3.0},"window_margin":{"left":12,"right":12,"top":12,"bottom":12},"button_padding":{"x":5.0,"y":3.0},"menu_margin":{"left":12,"right":12,"top":12,"bottom":12},"indent":18.0,"interact_size":{"x":40.0,"y":20.0},"slider_width":100.0,"slider_rail_height":8.0,"combo_width":100.0,"text_edit_width":280.0,"icon_width":14.0,"icon_width_inner":8.0,"icon_spacing":6.0,"default_area_size":{"x":600.0,"y":400.0},"tooltip_width":600.0,"menu_width":400.0,"menu_spacing":2.0,"indent_ends_with_horizontal_line":false,"combo_height":200.0,"scroll":{"floating":true,"bar_width":6.0,"handle_min_length":12.0,"bar_inner_margin":4.0,"bar_outer_margin":0.0,"floating_width":2.0,"floating_allocated_width":0.0,"foreground_color":true,"dormant_background_opacity":0.0,"active_background_opacity":0.4,"interact_background_opacity":0.7,"dormant_handle_opacity":0.0,"active_handle_opacity":0.6,"interact_handle_opacity":1.0}},"interaction":{"interact_radius":5.0,"resize_grab_radius_side":5.0,"resize_grab_radius_corner":10.0,"show_tooltips_only_when_still":true,"tooltip_delay":0.5,"tooltip_grace_time":0.2,"selectable_labels":true,"multi_widget_text_select":true},"visuals":{"dark_mode":true,"text_alpha_from_coverage":"TwoCoverageMinusCoverageSq","override_text_color":[207,216,220,255],"weak_text_alpha":0.6,"weak_text_color":null,"widgets":{"noninteractive":{"bg_fill":[0,0,0,0],"weak_bg_fill":[61,61,61,232],"bg_stroke":{"width":1.0,"color":[71,71,71,247]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[207,216,220,255]},"expansion":0.0},"inactive":{"bg_fill":[58,51,106,0],"weak_bg_fill":[8,8,8,231],"bg_stroke":{"width":1.5,"color":[48,51,73,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[207,216,220,255]},"expansion":0.0},"hovered":{"bg_fill":[37,29,61,97],"weak_bg_fill":[95,62,97,69],"bg_stroke":{"width":1.7,"color":[106,101,155,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.5,"color":[83,87,88,35]},"expansion":2.0},"active":{"bg_fill":[12,12,15,255],"weak_bg_fill":[39,37,54,214],"bg_stroke":{"width":1.0,"color":[12,12,16,255]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":2.0,"color":[207,216,220,255]},"expansion":1.0},"open":{"bg_fill":[20,22,28,255],"weak_bg_fill":[17,18,22,255],"bg_stroke":{"width":1.8,"color":[42,44,93,165]},"corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"fg_stroke":{"width":1.0,"color":[109,109,109,255]},"expansion":0.0}},"selection":{"bg_fill":[23,64,53,27],"stroke":{"width":1.0,"color":[12,12,15,255]}},"hyperlink_color":[135,85,129,255],"faint_bg_color":[17,18,22,255],"extreme_bg_color":[9,12,15,83],"text_edit_bg_color":null,"code_bg_color":[30,31,35,255],"warn_fg_color":[61,185,157,255],"error_fg_color":[255,55,102,255],"window_corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"window_shadow":{"offset":[0,0],"blur":7,"spread":5,"color":[17,17,41,118]},"window_fill":[11,11,15,255],"window_stroke":{"width":1.0,"color":[77,94,120,138]},"window_highlight_topmost":true,"menu_corner_radius":{"nw":6,"ne":6,"sw":6,"se":6},"panel_fill":[12,12,15,255],"popup_shadow":{"offset":[0,0],"blur":8,"spread":3,"color":[19,18,18,96]},"resize_corner_size":18.0,"text_cursor":{"stroke":{"width":2.0,"color":[197,192,255,255]},"preview":true,"blink":true,"on_duration":0.5,"off_duration":0.5},"clip_rect_margin":3.0,"button_frame":true,"collapsing_header_frame":true,"indent_has_left_vline":true,"striped":true,"slider_trailing_fill":true,"handle_shape":{"Rect":{"aspect_ratio":0.5}},"interact_cursor":"Crosshair","image_loading_spinners":true,"numeric_color_space":"GammaByte","disabled_alpha":0.5},"animation_time":0.083333336,"debug":{"debug_on_hover":false,"debug_on_hover_with_all_modifiers":false,"hover_shows_next":false,"show_expand_width":false,"show_expand_height":false,"show_resize":false,"show_interactive_widgets":false,"show_widget_hits":false,"show_unaligned":true},"explanation_tooltips":false,"url_in_tooltip":false,"always_scroll_the_only_direction":true,"scroll_animation":{"points_per_second":1000.0,"duration":{"min":0.1,"max":0.3}},"compact_menu_style":true}"#;

impl eframe::App for crate::PluginApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.process_to_hollow_file_dialog.update(ctx);
        self.plugin_dir_file_dialog.update(ctx);
        if self.first_run {
            self.first_run = false;
            match serde_json::from_str::<Style>(STYLE) {
                Ok(theme) => {
                    let style = std::sync::Arc::new(theme);
                    ctx.set_style(style);
                }
                Err(e) => log::info!("Error setting theme: {e:?}")
            };
        }
        
        if let Ok(diag_info) = self.diagnostics_rx.try_recv() {
            self.diag_info = diag_info;
        }

        if let Ok(pid) = self.pid_rx.try_recv() {
            log::info!("Got PID: {pid:?}");
            self.target_pid = Some(pid);
        }

        self.top_panel(ctx);
        self.page_content(ctx);
        self.warning_modal(ctx);
    }
}

impl crate::PluginApp {
    pub fn top_panel(&mut self, ctx: &Context) {
        TopBottomPanel::top(Id::new("Top Panel Plugin App")).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Plugin Path:             ");
                ui.text_edit_singleline(&mut self.plugin_dir);
                ui.add_space(10.);
                if ui.button("...").clicked() {
                    self.plugin_dir_file_dialog.pick_directory();
                }

                // Check if the user picked a file.
                if let Some(path) = self.plugin_dir_file_dialog.take_picked() {
                    self.plugin_dir = format!("{}", path.to_string_lossy());
                }

                ui.add_space(10.);

                if ui.button("Scan").clicked() {
                    self.scan_plugins();
                }

                ui.add_space(10.);
                
                ui.checkbox(&mut self.evasion_mode, "AV Evasion Mode");
                ui.checkbox(&mut self.thread_hijack_mode, "Thread Hijacking");
            });

            // Page navigation
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_page, tabs::InjectionPage::ClassicInjection, "Classic Injection");
                ui.selectable_value(&mut self.current_page, tabs::InjectionPage::ProcessHollowing, "Process Hollowing");
                ui.selectable_value(&mut self.current_page, tabs::InjectionPage::ReflectiveInjection, "Reflective Injection");
                ui.selectable_value(&mut self.current_page, tabs::InjectionPage::ManualMapping, "Manual Mapping");
                ui.selectable_value(&mut self.current_page,tabs::InjectionPage::Logs,  "Logs");
                ui.selectable_value(&mut self.current_page, tabs::InjectionPage::Help, "Help");
            });

            // Page-specific controls
            match self.current_page {
                tabs::InjectionPage::ProcessHollowing => self.process_hollowing_page_controls(ui),
                tabs::InjectionPage::ReflectiveInjection => self.reflective_injection_page_controls(ui),
                tabs::InjectionPage::ManualMapping => self.manual_mapping_page_controls(ui),
                _ => {}
            }
        }); 
    }

    pub fn page_content(&mut self, ctx: &Context) {
        CentralPanel::default().show(ctx, |ui| {
            match self.current_page {
                tabs::InjectionPage::ClassicInjection 
                    | tabs::InjectionPage::ReflectiveInjection
                    | tabs::InjectionPage::ManualMapping => self.classic_injection(ui),
                tabs::InjectionPage::ProcessHollowing => self.process_hollowing(ui),
                tabs::InjectionPage::Logs => egui_logger::logger_ui()
                    .warn_color(Color32::from_rgb(94, 215, 221)) 
                    .error_color(Color32::from_rgb(255, 55, 102)) 
                    .log_levels([true, true, true, false, false])
                    // there should be a way to set default false...
                    .enable_category("eframe".to_string(), false)
                    .enable_category("eframe::native::glow_integration".to_string(), false)
                    .enable_category("egui_glow::shader_version".to_string(), false)
                    .enable_category("egui_glow::painter".to_string(), false)
                    .show(ui),
                tabs::InjectionPage::Help => self.help(ui),
            }
        });
    }

    pub fn warning_modal(&mut self, ctx: &Context) {

        Window::new("Changes")
            .open(&mut self.open_diag_window)
            .show(ctx, |ui| {
                
                let base_address_before = self.diag_info.base_address_before;
                let base_address_after = self.diag_info.base_address_after;
                let entry_point_rva_before = self.diag_info.entry_point_rva_before;
                let entry_point_rva_after = self.diag_info.entry_point_rva_after;
                let rip_before = self.diag_info.rip_before;
                let rip_after = self.diag_info.rip_after;
                let rsp_before = self.diag_info.rsp_before;
                let rsp_after = self.diag_info.rsp_after;
                let rbp_before = self.diag_info.rbp_before;
                let rbp_after = self.diag_info.rbp_after;
                let tls_rva_before = self.diag_info.tls_rva_before;
                let tls_rva_after = self.diag_info.tls_rva_after;
                let tls_size_before = self.diag_info.tls_size_before;
                let tls_size_after = self.diag_info.tls_size_after;
                let reloc_rva_before = self.diag_info.reloc_rva_before;
                let reloc_rva_after = self.diag_info.reloc_rva_after;
                let reloc_size_before = self.diag_info.reloc_size_before;
                let reloc_size_after = self.diag_info.reloc_size_after;
                let sections_before = &self.diag_info.sections_before;
                let sections_after = &self.diag_info.sections_after;
                let imports_before = &self.diag_info.imports_before;
                let imports_after = &self.diag_info.imports_after;
                let exports_before = &self.diag_info.exports_before;
                let exports_after = &self.diag_info.exports_after;
                let tls_callbacks_before = &self.diag_info.tls_callbacks_before;
                let tls_callbacks_after = &self.diag_info.tls_callbacks_after;
                let reloc_blocks_before = &self.diag_info.reloc_blocks_before;
                let reloc_blocks_after = &self.diag_info.reloc_blocks_after;

                ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered(|ui| ui.heading("Process Hollowing Diagnostics"));
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(format!("Base Address: 0x{:X}", base_address_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", base_address_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("Entry Point RVA: 0x{:X}", entry_point_rva_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", entry_point_rva_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("RIP: 0x{:X}", rip_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", rip_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("RSP: 0x{:X}", rsp_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", rsp_after));
                        });
                    });


                    ui.horizontal(|ui| {
                        ui.label(format!("RBP: 0x{:X}", rbp_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", rbp_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("TLS Directory RVA: 0x{:X}", tls_rva_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", tls_rva_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("TLS Directory Size: 0x{:X}", tls_size_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", tls_size_after));
                        });
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label(format!("Relocation Table RVA: 0x{:X}", reloc_rva_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", reloc_rva_after));
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label(format!("Relocation Table Size: 0x{:X}", reloc_size_before));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(format!("0x{:X}", reloc_size_after));
                        });
                    });

                    ui.columns(2, |ui| {
                        ui[0].vertical_centered(|ui| {
                            if let Some(sections) = &sections_before {
                                ui.separator();
                                ui.heading("Sections Before");
                                for section in sections.iter() {
                                    ui.label(section.clone());
                                }
                            }
                        });
                        ui[1].vertical_centered(|ui| {
                            if let Some(sections) = &sections_after {
                                ui.separator();
                                ui.heading("Sections After");
                                for section in sections.iter() {
                                    ui.label(section.clone());
                                }
                            }
                        });
                    });

                    ui.columns(2, |ui| {
                        ui[0].vertical_centered(|ui| {
                            if let Some(imports) = &imports_before {
                                ui.separator();
                                ui.heading("Imports Before");
                                for import in imports.iter() {
                                    ui.label(import.clone());
                                }
                            }
                        });
                        ui[1].vertical_centered(|ui| {
                            if let Some(imports) = &imports_after {
                                ui.separator();
                                ui.heading("Imports After");
                                for import in imports.iter() {
                                    ui.label(import.clone());
                                }
                            }
                        });
                    });

                    ui.columns(2, |ui| {
                        ui[0].vertical_centered(|ui| {
                            if let Some(exports) = &exports_before {
                                ui.separator();
                                ui.heading("Exports Before");
                                for export in exports.iter() {
                                    ui.label(export.clone());
                                }
                            }
                        });
                        ui[1].vertical_centered(|ui| {
                            if let Some(exports) = &exports_after {
                                ui.separator();
                                ui.heading("Exports After");
                                for export in exports.iter() {
                                    ui.label(export.clone());
                                }
                            }
                        });
                    });

                    ui.columns(2, |ui| {
                        ui[0].vertical_centered(|ui| {
                            if let Some(tls_callbacks) = &tls_callbacks_before {
                                ui.separator();
                                ui.heading("TLS Callbacks Before");
                                for tls_callback in tls_callbacks.iter() {
                                    ui.label(format!("0x{tls_callback:X}"));
                                }
                            }
                        });
                        ui[1].vertical_centered(|ui| {
                            if let Some(tls_callbacks) = &tls_callbacks_after {
                                ui.separator();
                                ui.heading("TLS Callbacks After");
                                for tls_callback in tls_callbacks.iter() {
                                    ui.label(format!("0x{tls_callback:X}"));
                                }
                            }
                        });
                    });

                    ui.columns(2, |ui| {
                        ui[0].vertical_centered(|ui| {
                            if let Some(relocs) = &reloc_blocks_before {
                                ui.separator();
                                ui.heading("Relocations Before");
                                for reloc in relocs.iter() {
                                    ui.label(format!("0x{reloc:X}"));
                                }
                            }
                        });
                        ui[1].vertical_centered(|ui| {
                            if let Some(relocs) = &reloc_blocks_after {
                                ui.separator();
                                ui.heading("Relocations After");
                                for reloc in relocs.iter() {
                                    ui.label(format!("0x{reloc:X}"));
                                }
                            }
                        });
                    });
                });
            });
            
        if self.open_warning_modal {
            let modal = Modal::new(Id::new("Missing selected function modal"))
            .show(ctx, |ui| {
                match self.current_page {
                    tabs::InjectionPage::ClassicInjection 
                    | tabs::InjectionPage::ReflectiveInjection 
                    | tabs::InjectionPage::ManualMapping => {
                        if self.selected_function.is_none() {
                            ui.label("Missing Selected Function");
                        }
                        if self.selected_plugin.is_none() {
                            ui.label("Missing Selected Plugin");
                        }
                        if self.target_pid.is_none() {
                            ui.label("Missing Selected PID");
                        }
                    },
                    tabs::InjectionPage::ProcessHollowing => {
                        if self.process_to_hollow.is_empty() {
                            ui.label("Process to hollow is empty");
                        }
                    },
                    _ => {}
                }
            });

            if modal.should_close() {
                self.open_warning_modal = false;
            }
        }
    }
}