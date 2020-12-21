extern crate regex;
extern crate time;
extern crate xmltree;
extern crate getopts;
extern crate num_traits;
extern crate lru_cache;
extern crate fnv;

#[macro_use]
extern crate slog;
extern crate slog_stream;
extern crate slog_term;
extern crate slog_stdlog;
#[macro_use]
extern crate log;

use std::env;
use std::path::Path;
use std::thread;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::process::Command;
use std::io;
use std::fs::OpenOptions;
use std::collections::HashMap;

use num_traits::int::PrimInt;

use slog::DrainExt;

use getopts::Options;

mod observer;
mod config;

pub struct Hit {
    observer_name: String,
    ip: Ipv4Addr
}

struct JailEntry {
    time: i64,
    ip: Ipv4Addr,
}

struct LogFormat;

impl slog_stream::Format for LogFormat {
    fn format(&self,
              io: &mut dyn io::Write,
              rinfo: &slog::Record,
              _logger_values: &slog::OwnedKeyValueList)
              -> io::Result<()> {
        let msg = format!("{} - {} - {}\n", time::now().strftime("%b %d %H:%M:%S").unwrap(), rinfo.level(), rinfo.msg());
        // let _ = try!(io.write_all(msg.as_bytes()));
        // Ok(())
        io.write_all(msg.as_bytes())?;
        Ok(())
    }
}

fn unjail_thread(jail: Arc<Mutex<Vec<JailEntry>>>, sleep_for: u64, command: String, simulate:bool) {
    thread::spawn(move || {
        loop {
            {
                let current_time = time::get_time().sec;
                let mut entries = jail.lock().unwrap();
                do_while(&mut entries, |ref it| it.time <= current_time, &unjail, &command, simulate);
            }
            thread::sleep(Duration::from_millis(sleep_for));
        }
    });
}

fn do_while<T, F>(mut vec: &mut Vec<T>, check: F, execute: &dyn Fn(&mut Vec<T>, usize, &str, bool), command: &str, simulate: bool)
    where F: Fn(&T) -> bool
{
    loop {
        let removed = vec.iter()
            .position(|it| check(it))
            .map(|e| execute(&mut vec, e, command, simulate))
            .is_some();
        if !removed { break }
    }
}

fn unjail(entries: &mut Vec<JailEntry>, index: usize, command: &str, simulate: bool) {
    info!("Unjailing: {}", entries[index].ip );
    if execute_process(&command, &entries[index].ip, simulate) {
        entries.remove(index);
    }
}

fn dojail(entries: &mut Vec<JailEntry>, jail_counter: &mut HashMap<Ipv4Addr, u32>, hit: &Hit, jail_time: i64, command: &str, simulate: bool) -> bool {


    //let mut effective_jail_time = jail_time;
    let mut found_existing_item = false;

    if let Some(existing_item) = entries.iter_mut().find( |it| it.ip == hit.ip) {
        existing_item.time = time::get_time().sec + jail_time;
        found_existing_item = true;
    }

    if found_existing_item {
        entries.sort_by(|a, b| a.time.cmp(&b.time));
        return false;
    }

    let jail_count = jail_counter.entry(hit.ip).or_insert(0);
    *jail_count = *jail_count + 1;

    info!("Jailing {} - count: {}: {}", hit.observer_name, jail_count, hit.ip);
    if execute_process(command, &hit.ip, simulate) {

        entries.push(
            JailEntry{
                time: time::get_time().sec + jail_time * 6.pow(*jail_count-1),
                ip: hit.ip,
            }
        );

    }

    entries.sort_by(|a, b| a.time.cmp(&b.time));
    true

}

fn execute_process(command: &str, ip: &Ipv4Addr, simulate: bool) -> bool {

    let mut parsed_command = String::from_str(command).unwrap().replace("{ip}", &ip.to_string());
    info!("{:?}", parsed_command);

    let program_name_offset = parsed_command.find(" ").unwrap_or(parsed_command.len());
    let program_name : String = parsed_command.drain(..program_name_offset).collect();
    let arguments_string = parsed_command.trim();

    if simulate {
        info!("Simulated command: {} with arguments {}", program_name, arguments_string);
        return true;
    }
    
    let status;

    if !arguments_string.is_empty() {

        info!("Parsed arguments are {}", arguments_string);
        let arguments : Vec<String> = arguments_string.split_whitespace().map( |s| String::from_str(s).unwrap() ).collect();
        // let arguments : Vec<String> = env::args().collect();
        status = match Command::new(&program_name)
            .args(&arguments)
            .status() {
                Ok(stat) => stat,
                Err(why) => {
                    error!("Error executing command {} with argument {:?}: {}", program_name, arguments, why);
                    error!("The paramenter to the commans are{}", arguments.iter().fold(String::new(), |acc, arg| acc + &arg));
                    error!("The argument_string_ {}", arguments_string);
                    return false
            }
        };
    } else {
        status = match Command::new(&program_name)
            .status() {
            Ok(stat) => stat,
            Err(why) => {
                error!("Error executing command {}: {}", program_name, why);
                return false
            }
        };
    }

    if status.success() {
        return true;
    }

    error!("Error executing command: {} {}", program_name, arguments_string);
    false
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn get_default_config() -> Option<String> {
    let default_paths = ["/etc/heimdall.xml", "heimdall.xml"];
    match default_paths.iter().find( |path| {
        Path::new(&path).exists()
    }) {
        Some(s) => Some(String::from_str(s).unwrap()),
        None => None
    }
}

fn main() {

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "set configuration file", "path to configuration file");
    opts.optflag("a", "all", "read files from beginning.");
    opts.optflag("s", "simulate", "don't execute commands.");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let config_path = match matches.opt_str("c") {
        Some(path) => path,
        None => match get_default_config() {
            Some(path) => path,
            None => {
                println!("Error: Could find no configuration file.");
                return;
            }
        }
    };

    let config = match config::Config::parse(&config_path) {
        Ok(config) => config,
        Err(message) => {
            println!("Error: {}", message);
            return;
        }
    };

    //Logging ins File und auch an die Console.
    let file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.logfile) {
        Ok(f) => f,
        Err(message) => {
            println!("Could not open logfile {}: {}", &config.logfile, message);
            return;
        }
    };

    let console_drain = slog_term::streamer().build();
    let file_drain = slog_stream::stream(file, LogFormat);
    let logger = slog::Logger::root(slog::duplicate(console_drain, file_drain).fuse(), o!());
    slog_stdlog::set_logger(logger).unwrap();

    info!("Initialized successfully.");

    let read_from_start = matches.opt_present("a");
    let simulate = matches.opt_present("s");

    if read_from_start {
        info!("Reading files from start.");
    }

    if simulate {
        info!("Simulation mode activated.");
    }

    let mut jail_counter : HashMap<Ipv4Addr, u32> = HashMap::new();
    let jail = Arc::new(Mutex::new(Vec::new()));
    unjail_thread(jail.clone(), 10000, config.command_unjail , simulate);

    let (tx, rx) = mpsc::channel();
    for observer in config.observers {
        info!("Starting observer {}.", observer.name);
        let _ = match observer.start(tx.clone(), read_from_start, 5) {
            Ok(flag) => flag,
            Err(message) => {
                error!("{}", message);
                println!("Error: {}", message);
                return;
            }
        };
    }

    loop {
        let hit = rx.recv().unwrap();
        {
            let mut entries = jail.lock().unwrap();
            dojail(&mut entries, &mut jail_counter, &hit, config.jail_time, &config.command_jail, simulate);
        }
    }

}