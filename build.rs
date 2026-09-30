fn main() {
    let sources = [
        "vendor/shrincs/src/address.cpp",
        "vendor/shrincs/src/hash.cpp",
        "vendor/shrincs/src/pors_fp.cpp",
        "vendor/shrincs/src/shrincs.cpp",
        "vendor/shrincs/src/uxmss.cpp",
        "vendor/shrincs/src/wots_c.cpp",
        "vendor/shrincs/src/xmss.cpp",
        "vendor/shrincs/src/ffi.cpp",
    ];

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .opt_level(3)
        .warnings(false)
        .define("SHRINCS_B32", None)
        .include("vendor/shrincs/include")
        .files(sources)
        .compile("shrincs");

    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=vendor/shrincs/include");
    println!("cargo:rerun-if-changed=vendor/shrincs/src");
}
