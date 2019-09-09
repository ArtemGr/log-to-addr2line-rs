//#[macro_use] extern crate lazy_static;
#[macro_use] extern crate unwrap;

use gstuff::binprint;
use regex::{Captures, Regex};
use std::fs;
use std::io::{self, BufRead};
use std::process::{Command, Stdio};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "log-to-addr2line-rs")]
struct Opt {
    /// Executable.
    #[structopt(short, long)]
    exe: String,
    /// Log file.
    #[structopt(short, long)]
    log: String,
    /// How to run "addr2line".
    #[structopt(long)]
    addr2line: Option<String>,
    /// How to run "rustfilt".  
    /// (Install it with "cargo install rustfilt").
    #[structopt(long)]
    rustfilt: Option<String>
}

fn android_ (opt: &Opt, line: &str, caps: Captures) {
    let addr2line = opt.addr2line.as_ref().map (|s| &s[..]) .unwrap_or ("addr2line");

    println!();
    println! ("{}", line);
    let num = unwrap! (caps.get (1)) .as_str();
    let addr = unwrap! (caps.get (2)) .as_str();
    println! ("num {} addr {}", num, addr);

    let mut cmd = Command::new (addr2line);
    cmd.arg (format! ("--exe={}", opt.exe));
    cmd.arg ("--functions");
    cmd.arg ("--demangle");
    cmd.arg (addr);
    cmd.stdout (Stdio::inherit());
    cmd.stderr (Stdio::inherit());
    let status = unwrap! (cmd.status());
    if !status.success() {println! ("{:?}", status)}
}

fn ips_ (opt: &Opt, line: &str, caps: Captures) {
    let _binary_immage_name = unwrap! (caps.get (1)) .as_str();
    let address = unwrap! (caps.get (2)) .as_str();
    let load_address = unwrap! (caps.get (3)) .as_str();

    println!();
    println! ("{}", line);

    let mut cmd = Command::new ("atos");
    cmd.arg ("-arch") .arg ("arm64");
    cmd.arg ("-o") .arg (&opt.exe);
    cmd.arg ("-l") .arg (load_address);
    cmd.arg (address);
    let output = unwrap! (cmd.output(), "!atos");

    if !output.stderr.is_empty() {
        println! ("atos error: {}", binprint (&output.stderr, b'.'));
        return
    }

    if !output.status.success() {
        println! ("atos error");
        return
    }

    let stdout = unwrap! (String::from_utf8 (output.stdout), "!utf-8");
    let stdout = stdout.trim();
    println! ("{}", stdout);

    /*
    lazy_static! {
        static ref RS: Regex = unwrap! (Regex::new (r" \(\w+\.rs:\d+\)$"));
    }
    if !RS.is_match (stdout) {
        println! ("{}", stdout);
        return
    }

    let raw_symbol = stdout;
    let rustfilt = opt.rustfilt.as_ref().map (|s| &s[..]) .unwrap_or ("rustfilt");
    let mut cmd = Command::new (rustfilt);
    cmd.stdin (Stdio::piped());
    cmd.stdout (Stdio::piped());
    let mut rustfilt = unwrap! (cmd.spawn(), "!rustfilt");
    let mut stdin = unwrap! (rustfilt.stdin.take().ok_or ("!stdin"));
    let mut stdout = unwrap! (rustfilt.stdout.take().ok_or ("!stdin"));
    unwrap! (stdin.write_all (raw_symbol.as_bytes()));
    drop (stdin);
    assert! (unwrap! (rustfilt.wait()) .success());
    let mut buf = String::new();
    unwrap! (stdout.read_to_string (&mut buf));
    println! ("filtered: {}", buf);*/
}

fn main() {
    let opt = Opt::from_args();

    let log_file = unwrap! (fs::File::open (&opt.log), "Can't open the log {:?}", opt.log);
    let log_file = io::BufReader::new (log_file);

    // Currently only Android stack traces. Might support other formats in the future.
    // 08-06 05:24:35.985 21317 21317 F DEBUG   :     #00 pc 00123456  /data/data/package/app-folder/binary
    let android = unwrap! (Regex::new (r"^\d+-\d+ \d+:\d+:\d+\.\d+ \d+ \d+ F DEBUG +: +#(\d+) pc (\w+) +/"));

    // Standard iOS crash log, such as "Runner-2019-09-09-182634.ips".
    // 0   libsystem_kernel.dylib        	0x00000001b42d9c60 0x1b42c1000 + 101472
    // https://developer.apple.com/library/archive/technotes/tn2151/_index.html#//apple_ref/doc/uid/DTS40008184-CH1-SYMBOLICATE_WITH_ATOS
    let ips = unwrap! (Regex::new (r"^\d+\s+([\w\.]+)\s+(0x[0-9a-f]+) (0x[0-9a-f]+) \+ \d+"));

    for line in log_file.lines() {
        let line = match line {Ok (l) => l, Err (err) => {
            eprintln! ("Error getting a log line: {}", err); continue}};
        if let Some (caps) = android.captures (&line) {
            android_ (&opt, &line, caps)
        } else if let Some (caps) = ips.captures (&line) {
            ips_ (&opt, &line, caps)
        }
    }
}
