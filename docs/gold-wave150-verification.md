# W150 - hosted native GUI fixture compile recovery

Full CI35591362095 on cee40a6c failed both stable Linux and advisory beta GUI
compilation. The complete logs identified two independent fixture defects.

The W138 Skill-autonomy helper and callback test were nested in the terminal
launcher rather than the native GUI test module. This made fixture imports
inaccessible and registered an unnameable inner test. The whole published
helper/test block is now moved intact into w58_gui_callback_runtime_tests,
where its existing fixture helpers and environment lock are owned. Its exact
custom macOS harness identity is preserved.

The W130 stale-inventory test queued an Rc<Cell<Option<bool>>> through Slint's
Send-required event-loop closure. Its completion carrier now uses
Arc<Mutex<Option<bool>>>. The drain still asserts the same rejected stale
snapshot result, Some(false); no assertion or lint requirement is weakened.

Root verified the moved block against the exact published source and reviewed
the completion carrier. W142 working code is separate from these repairs.
Fresh hosted compilation and callback runtime remain required. No local
compiler, formatter, parser, test, fixture, product or GUI was run and no Road
checkbox is closed.
