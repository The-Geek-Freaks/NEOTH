//! Execute the production GUI controller's ownership tests without linking the
//! Slint desktop binary. The module is shared by path so this harness cannot
//! silently drift into a second implementation.

#[path = "../../neothd-gui/src/code_map_controller.rs"]
mod code_map_controller;
