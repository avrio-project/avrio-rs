extern crate ansi_term;

use ansi_term::Colour;

fn red(text) {
    println!(Colour::Red.paint(text))
}
fn blue(text) {
    println!(Colour::Blue.paint(text))
}
fn green(text) {
    println!(Colour::Green.paint(text))
}
fn white(text) {
    println!(Colour::White.paint(text))
}
fn yellow(text) {
    println!(Colour::Yellow.paint(text))
}

fn main() {
    white('test white');
    red('test red');
    blue('test blue');
    white('test white repeat');
    green('test green');
