use std::io::BufReader;
use std::fs::File;
// use std::error::Error;

use regex::Regex;
use regex::RegexSet;
use xmltree::Element;

use observer;
use observer::LogPattern;

pub struct Config {
    pub logfile: String,
    pub command_jail: String,
    pub command_unjail: String,
    pub jail_time : i64,
    pub observers : Vec<observer::FileObserver>
}

impl Config {

    pub fn parse(filename : &str) -> Result<Config, String> {
        let mut observers : Vec<observer::FileObserver> = Vec::new();

        let f = match File::open(filename){
            Ok(file) => file,
            Err(e) => return Err(format!("Could not open {}: {}", filename, e.to_string()))
        };

        let configuration_file_reader = BufReader::new(f);

        let mut el_configuration = Element::parse(configuration_file_reader).unwrap();

        let s_logfile = match el_configuration.take_child("logfile") {
            Some(el) => match el.text {
                Some(command) => command,
                None => return Err("Invalid XML: logfile is empty.".to_string())
            },
            None => return Err("Invalid XML: logfile element is missing.".to_string())
        };

        let s_command_jail = match el_configuration.take_child("command_jail") {
            Some(el) => match el.text {
                Some(command) => command,
                None => return Err("Invalid XML: command_jail is empty.".to_string())
            },
            None => return Err("Invalid XML: command_jail element is missing.".to_string())
        };

        let s_command_unjail = match el_configuration.take_child("command_unjail") {
            Some(el) => match el.text {
                Some(command) => command,
                None => return Err("Invalid XML: command_unjail is empty.".to_string())
            },
            None => return Err("Invalid XML: command_unjail element is missing.".to_string())
        };

        let el_observers = match el_configuration.take_child("observers") {
            Some(e) => e,
            None => return Err("Invalid XML: observers element is missing.".to_string())
        };

        let jail_time = match el_observers.attributes.get("jail_time"){
            Some(attr) => match attr.parse::<i64>() {
                Ok(number) => number,
                Err(_) => return Err("Invalid data format: jail_time has to be an integer.".to_string())
            },
            None => return Err("Invalid XML: attribute jail_time is missing.".to_string())
        };

        for mut el_observer in el_observers.children {

            let el_patterns = match el_observer.take_child("patterns"){
                Some(e) => e,
                None => return Err("Invalid XML: patterns element is missing.".to_string())
            };

            let mut observer_patterns : Vec<LogPattern> = Vec::new();
            let mut str_regexset_patterns : Vec<String> = Vec::new();

            for el_pattern in el_patterns.children {

                let s_regex = match el_pattern.text {
                    Some(text) => text,
                    None => return Err("Invalid XML: regex is missing.".to_string())
                };

                let (pattern, str_regex) = match create_pattern(&s_regex) {
                    Ok(pat) => pat,
                    Err(e) => return Err(e)
                };

                observer_patterns.push(pattern);
                str_regexset_patterns.push(str_regex);

            }

            let s_name = match el_observer.attributes.get("name"){
                Some(attr) => attr.clone(),
                None => return Err("Invalid XML: attribute name is missing.".to_string())
            };

            let s_file_path = match el_observer.take_child("file") {
                Some(child) => match child.text {
                    Some(text) => text,
                    None => return Err("Invalid XML: filename is missing.".to_string())
                },
                None => return Err("Invalid XML: file is missing.".to_string())
            };

            let u_limit_minutes = match el_observer.attributes.get("limit_minutes"){
                Some(attr) => match attr.parse::<u8>() {
                    Ok(number) => number,
                    Err(_) => return Err("Invalid data format: limit_minutes has to be an integer.".to_string())
                },
                None => return Err("Invalid XML: attribute limit_minutes is missing.".to_string())
            };

            let u_limit_count = match el_observer.attributes.get("limit_count"){
                Some(attr) => match attr.parse::<u32>() {
                    Ok(number) => number,
                    Err(_) => return Err("Invalid data format: limit_count has to be an integer.".to_string())
                },
                None => return Err("Invalid XML: attribute limit_count is missing.".to_string())
            };

            let observer = observer::FileObserver {
                name: s_name,
                file_path: s_file_path,
                patterns: observer_patterns,
                pattern_set: RegexSet::new(&str_regexset_patterns).unwrap(),
                limit_minutes: u_limit_minutes,
                limit_count: u_limit_count
            };

            observers.push(observer);

        }

        Ok(Config {
            logfile: s_logfile,
            command_jail: s_command_jail,
            command_unjail: s_command_unjail,
            jail_time: jail_time,
            observers: observers,
        })

    }

}

/*
fn get_for_string<'a>(s: &'a str, pos_ip : &'a mut usize, pos_hour: &'a mut usize, pos_minute : &'a mut usize) ->  &'a mut usize {
    if s == "ip" { return pos_ip; }
    if s == "hour" { return pos_hour; }
    pos_minute
}
*/

fn create_pattern(s: &String) -> Result<(LogPattern, String), String> {

    let raw = s.replace("{hh:mm:ss}", r"{h}:{m}:\d\d");

    let regex_groups : String = raw
        .replace("{ip}", "({ip})")
        .replace("{h}", "({h})")
        .replace("{m}", "({m})");

    let str_regex = raw
        .replace("{ip}", r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        .replace("{h}", r"(\d?\d)")
        .replace("{m}", r"(\d?\d)");

    let regex = match Regex::new(&str_regex) {
        Ok(regex) => regex,
        Err(err) => return Err(format!("Invalid Regex: {}: {}", &str_regex, err.to_string()))
    };

    fn get_capture_group(haystack : &str, needle : &str) -> Option<usize> {

        let str_start_part = match haystack.find(needle) {
            Some(index) => &haystack[..index],
            None => return None
        };

        Some(
            str_start_part.chars()
                .filter(|c| *c == '(')
                .count()
        )

    }

    let pos_ip = match get_capture_group(&regex_groups, "{ip}") {
        Some(count) => count,
        None => return Err(format!("Invalid Regex: {}: ip is missing.", &s))
    };

    let pos_hour = match get_capture_group(&regex_groups, "{h}") {
        Some(count) => count,
        None => return Err(format!("Invalid Regex: {}: h is missing.", &s))
    };

    let pos_minute = match get_capture_group(&regex_groups, "{m}") {
        Some(count) => count,
        None => return Err(format!("Invalid Regex: {}: m is missing.", &s))
    };

    Ok(
        (LogPattern{
            regex: regex,
            pos_hour: pos_hour,
            pos_minute: pos_minute,
            pos_ip: pos_ip
        },str_regex)
    )

}