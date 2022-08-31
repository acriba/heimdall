use Hit;

use std::io::BufReader;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::fs;
use std::fs::File;
use std::thread;
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::net::IpAddr;
use std::str::FromStr;
//use std::collections::HashMap;
// use std::error::Error;

use regex::Regex;
use regex::RegexSet;

use lru_cache::LruCache;
use fnv::FnvHasher;
use std::hash::BuildHasherDefault;

type FnvLruCache<K, V> = LruCache<K, V, BuildHasherDefault<FnvHasher>>;

pub struct FileObserver {
    pub name: String,
    pub file_path: String,
    pub patterns: Vec<LogPattern>,
    pub pattern_set: RegexSet,
    pub limit_count: u32,
    pub limit_minutes: u8,
}

pub struct HourStat {
    hour: u8,
    minutes: [u32; 60]
}

pub struct LogPattern {
    pub regex: Regex,
    pub pos_hour: usize,
    pub pos_minute: usize,
    pub pos_ip: usize,
}

pub struct PatternResult {
    hour: u8,
    minute: u8,
    ip: IpAddr,
}

impl HourStat {

    /*
    fn new(hour:u8) -> HourStat {
        HourStat {
            hour: hour,
            minutes: [0;60]
        }
    }
    */

    fn new(hour:u8, minute:u8, count:u32) -> HourStat {
        let mut minutes = [0; 60];
        minutes[minute as usize] += count;
        HourStat {
            hour: hour,
            minutes: minutes
        }
    }

    fn add(&mut self, hour:u8, minute:u8, count:u32) {
        //let abs_difference = if self.hour >= hour { self.hour - hour } else { hour - self.hour };
        if abs_difference(&self.hour, &hour) > 1 {
            self.minutes = [0;60];
        }
        self.hour = hour;
        self.minutes[minute as usize] += count;
    }

    fn sum(&mut self, hour:u8, minute:u8, interval:&u8) -> u32 {
        if abs_difference(&self.hour, &hour) > 1 { return 0; }
        let mut total = 0;
        for i in 0..*interval {
            let index = if minute >= i { minute-i } else { 60+minute-i };
            total += self.minutes[index as usize];
        }
        total
    }

}

fn abs_difference(a: &u8, b: &u8) -> u8 {
    if a >= b  { a-b } else { b-a }
}

impl FileObserver {

    pub fn start(self, tx: Sender<Hit>, read_from_start: bool, sleep_time: u64) -> Result<bool, String> {

        //let (tx, rx) = mpsc::channel();

        let mut size: u64 = match fs::metadata(&self.file_path) {
            Ok(meta) => meta.len(),
            Err(why) => return Err(format!("Could not read file: {}: {}", self.file_path, why.to_string()))
        };

        info!("observing file: {}", self.file_path);

        thread::spawn(move || {

            //let mut ip_statistics : HashM<IpAddr, HourStat> = HashMap::new();

            let mut ip_statistics : FnvLruCache<IpAddr, HourStat> = LruCache::with_hasher(5000, Default::default());

            let mut log_line = String::new();

            let f = File::open(&self.file_path).expect("Unable to open file");
            let mut reader = BufReader::new(f);
            if !read_from_start {
                reader.seek(SeekFrom::End(0)).unwrap();
            }

            loop {
                let current_size: u64 = match fs::metadata(&self.file_path) {
                    Ok(val) => val.len(),
                    Err(_) => {
                        let reopen_file = match File::open(&self.file_path) {
                            Ok(val) => val,
                            Err(_) => continue
                        };
                        reader = BufReader::new(reopen_file);
                        continue
                    }
                };
                if current_size < size {
                    let _ = match reader.seek(SeekFrom::End(0)) {
                        Ok(val) => val,
                        Err(_) => continue
                    };
                    size = current_size;
                }
                'lbl_continue: while match reader.read_line(&mut log_line) {
                    Ok(val) => val,
                    Err(_) => continue 'lbl_continue
                } > 0 {
                    if let Some(hit) = check_patterns(&self.pattern_set, &self.patterns, &log_line) {
                        /*
                        if ip_statistics.len() > 5000 {
                            info!("Cleared hashmap size was greater 5000.");
                            ip_statistics.clear();
                        }
                        */
                        let interval_hits = get_updated_interval_hits(&mut ip_statistics, &hit, &self.limit_minutes);
                        if interval_hits >= self.limit_count {
                            ip_statistics.remove(&hit.ip);
                            tx.send(Hit{
                                observer_name: self.name.clone(),
                                ip: hit.ip
                            }).unwrap();
                        }
                    }
                    log_line.clear();
                }
                thread::sleep(Duration::from_millis(sleep_time));
            }
        });

        Ok(true)
    }

}

fn get_updated_interval_hits(ip_statistics: &mut FnvLruCache<IpAddr, HourStat>, hit: &PatternResult, limit_minutes: &u8) -> u32 {

    if let Some(hour_stat) = ip_statistics.get_mut(&hit.ip) {
        hour_stat.add(hit.hour, hit.minute, 1);
        return hour_stat.sum(hit.hour, hit.minute, limit_minutes);
    }

    ip_statistics.insert(hit.ip, HourStat::new(hit.hour, hit.minute, 1));
    1
}

fn check_patterns(regex_set: &RegexSet, patterns: &Vec<LogPattern>, line: &str) -> Option<PatternResult> {

    if regex_set.is_match(line) {

        let first_match = regex_set.matches(line).iter().next().unwrap();
        let ref log_pattern = patterns[first_match];

        if let Some(caps) = log_pattern.regex.captures(line) {

            let hour = caps.at(log_pattern.pos_hour).and_then( |s| match s.parse::<u8>() {
                Ok(number) => Some(number),
                Err(_) => None
            } );

            let hour = match hour {
                Some(number) => number,
                None => return None
            };

            let minute = caps.at(log_pattern.pos_minute).and_then( |s| match s.parse::<u8>() {
                Ok(number) => Some(number),
                Err(_) => None
            } );

            let minute = match minute {
                Some(number) => number,
                None => return None
            };

            let ip = caps.at(log_pattern.pos_ip).and_then( |s| match IpAddr::from_str(s) {
                Ok(ip) => Some(ip),
                Err(_) => None
            });

            let ip = match ip {
                Some(number) => number,
                None => return None
            };

            return Some(PatternResult{hour: hour, minute: minute, ip: ip});

        }

    }

    None
}

#[cfg(test)]
mod tests {
    use regex::RegexSet;
    use config::create_pattern;

    use super::*;

    #[test]
    fn checkpatterns_ipv4() {
        let mut pattern_strs = Vec::<String>::new();
        let mut patterns = Vec::<LogPattern>::new();

        let (pattern, pattern_str) = create_pattern(&"{hh:mm:ss}.*Failed password.*from {ip}".to_owned()).unwrap();
        pattern_strs.push(pattern_str);
        let regex_set = RegexSet::new(pattern_strs).unwrap();
        patterns.push(pattern);

        let check = check_patterns(&regex_set, &patterns, "10:00:00 Failed password from 192.168.1.1").unwrap();
        assert_eq!(check.hour, 10);
        assert_eq!(check.minute, 00);
        assert_eq!(check.ip, IpAddr::from_str("192.168.1.1").unwrap());
    }

    #[test]
    fn checkpatterns_ipv6() {
        let mut pattern_strs = Vec::<String>::new();
        let mut patterns = Vec::<LogPattern>::new();

        let (pattern, pattern_str) = create_pattern(&"{hh:mm:ss}.*Failed password.*from {ip}".to_owned()).unwrap();
        pattern_strs.push(pattern_str);
        let regex_set = RegexSet::new(pattern_strs).unwrap();
        patterns.push(pattern);

        for ip in &["fe80::60:24:8d:19", "::1", "::ffff:192.168.1.1"] {
            let check = check_patterns(&regex_set, &patterns, &format!("10:00:00 Failed password from {}", ip)).unwrap();
            assert_eq!(check.hour, 10);
            assert_eq!(check.minute, 00);
            assert_eq!(check.ip, IpAddr::from_str(ip).unwrap());
        }
    }
}
