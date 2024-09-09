use std::{env, path::PathBuf};

// Create rust bindings to libsel4 (which is generated when building seL4)
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search={}", out_dir.display());

    let bindings = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <sel4/sel4.h>")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg("-IseL4/install/libsel4/include")
        .use_core()
        .generate()
        .unwrap();

    let out_file = out_dir.join("sel4_bindings.rs");

    bindings.write_to_file(&out_file).unwrap();
}
