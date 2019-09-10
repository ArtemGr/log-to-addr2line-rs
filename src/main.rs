#[macro_use] extern crate lazy_static;
#[macro_use] extern crate unwrap;

use gstuff::binprint;
use regex::{Captures, Regex};
use std::fs;
use std::io::{self, BufRead, Read, Write};
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

    // finding dSYM: https://stackoverflow.com/a/36092643/257568
    // `dwarfdump --uuid $binary` (https://stackoverflow.com/a/9990995/257568)
    // cf. https://developer.apple.com/library/archive/technotes/tn2151/_index.html#//apple_ref/doc/uid/DTS40008184-CH1-SYMBOLICATIONTROUBLESHOOTING
    // 
    // There should be a way to verify that a given dSYM matches the given crash log.
    // I didn't yet had a chance to check it, but based on the docs above it seems that:
    // 
    // The first "Binary Images" line, such as
    // 
    //     0x10273c000 - 0x103673fff Runner arm64  <bf91fb5f03df338a918e3bda951b0577> /var/containers/Bundle/Application/C9A45E31-4A31-49D3-97D9-B085ED0D44C0/Runner.app/Runner
    // 
    // should match the UUID of the `dwarfdump --uuid` of the dSYM.
    // Alternatively,
    // 
    //     mdfind "com_apple_xcode_dsym_uuids == BF91FB5F-03DF-338A-918E-3BDA951B0577"
    // 
    // can be used to find the right dSYM.

    // Not sure whether non-Runner addresses can be symbolicated with the Runner dSYM.

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

    // core::ptr::real_drop_in_place::he308621a82284088 (in Runner) (mod.rs:175)
    lazy_static! {static ref RS_HASH: Regex = unwrap! (Regex::new (
        r"(?x) ^(.*?[\w\$]) :: h[0-9a-f]{16} \s\(in\s[\w\.]+\) \s\([\w\.:<>\s]+\)$"));}
    let rs_hash = RS_HASH.captures (stdout);
    let rs_hash = match rs_hash {
        Some (caps) => caps,
        None => {
            println! ("{}", stdout);
            return
        }
    };
    let symbol = unwrap! (rs_hash.get (1)) .as_str();
    println! ("{}", symbol);

    if 1==0 {  // rustfilt doesn't grok the iOS output so far
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
        println! ("filtered: {}", buf);
    }
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
        } else if line.starts_with ("Thread ") {
            println! ("{}", line);
        }
    }
}
