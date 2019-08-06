#[macro_use] extern crate unwrap;

use regex::Regex;
use std::env::args;
use std::fs;
use std::io::{self, BufRead};
use std::process::{Command, Stdio};

fn main() {
    let mut exe = None;
    let mut log = None;
    let mut addr2line = String::from ("addr2line");

    for arg in args() {
        if arg.starts_with ("--exe=") {exe = Some (String::from (&arg[6..]))}
        if arg.starts_with ("--log=") {log = Some (String::from (&arg[6..]))}
        if arg.starts_with ("--addr2line=") {addr2line = String::from (&arg[12..])}
    }

    let exe = match exe {Some (v) => v, None => panic! ("Please use --exe=$path to specify the executable")};
    let log = match log {Some (v) => v, None => panic! ("Please use --log=$path to specify the log")};

    let log_file = unwrap! (fs::File::open (&log), "Can't open the log {:?}", log);
    let log_file = io::BufReader::new (log_file);

    // Currently only Android stack traces. Might support other formats in the future.
    // 08-06 05:24:35.985 21317 21317 F DEBUG   :     #00 pc 00123456  /data/data/package/app-folder/binary
    let re = unwrap! (Regex::new (r"^\d+-\d+ \d+:\d+:\d+\.\d+ \d+ \d+ F DEBUG +: +#(\d+) pc (\w+) +/"));

    for line in log_file.lines() {
        let line = match line {Ok (l) => l, Err (err) => {
            eprintln! ("Error getting a log line: {}", err); continue}};
        let caps = match re.captures (&line) {Some (c) => c, None => continue};
        println!();
        println! ("{}", line);
        let num = unwrap! (caps.get (1)) .as_str();
        let addr = unwrap! (caps.get (2)) .as_str();
        println! ("num {} addr {}", num, addr);

        let mut cmd = Command::new (&addr2line);
        cmd.arg (format! ("--exe={}", exe));
        cmd.arg ("--functions");
        cmd.arg ("--demangle");
        cmd.arg (addr);
        cmd.stdout (Stdio::inherit());
        cmd.stderr (Stdio::inherit());
        let status = unwrap! (cmd.status());
        if !status.success() {println! ("{:?}", status)}
    }
}
