//! `cargo run --example demo`: what a Craft app does on start.
fn main() {
    craft_license::enforce("Demo");
    println!("license ok: {:?}", craft_license::check(false));
}
