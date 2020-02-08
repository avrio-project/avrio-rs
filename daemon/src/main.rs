extern crate ansi_term;

use ansi_term::Colour;

fn red(text: String) {
    println!(Colour::Red.paint(text))
}
fn blue(text: String) {
    println!(Colour::Blue.paint(text))
}
fn green(text: String) {
    println!(Colour::Green.paint(text))
}
fn white(text: String) {
    println!(Colour::White.paint(text))
}
fn yellow(text: String) {
    println!(Colour::Yellow.paint(text))
}

fn main() {
    white("test white");
    red("test red");
    blue("test blue");
    white("test white repeat");
    green("test green");
}
