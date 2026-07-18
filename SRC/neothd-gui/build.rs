fn main() {
    // main.slint is at the Slint compiler's codegen recursion ceiling (4400+
    // lines; STATUS_STACK_OVERFLOW on further growth — BUILD_LOG G19). Run the
    // compile on a thread with a 256 MiB stack instead of the default 8 MiB.
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(|| slint_build::compile("ui/main.slint").expect("compile Slint UI"))
        .expect("spawn slint build thread")
        .join()
        .expect("join slint build thread");
}
