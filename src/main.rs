use std::io::{BufRead, Write};

mod logger;
mod openai;

use crate::logger::Logger;

#[cfg(debug_assertions)]
const DEBUG: bool = true;
#[cfg(not(debug_assertions))]
const DEBUG: bool = false;

const WHITELIST: &[&str] = &["jpg", "jpeg", "png", "svg"];

// TODO: a lot of this could probably be abstracted into a library,
//       along with the same code in Dewey

fn create_if_nonexistent(path: &std::path::PathBuf) {
    if !path.exists() {
        match std::fs::create_dir_all(&path) {
            Ok(_) => (),
            Err(e) => panic!("Failed to create directory: {:?}, {}", path, e),
        };
    }
}

fn touch_file(path: &std::path::PathBuf) {
    if !path.exists() {
        match std::fs::File::create(&path) {
            Ok(_) => (),
            Err(e) => panic!("Failed to create file: {:?}, {}", path, e),
        };
    }
}

pub fn get_home_dir() -> std::path::PathBuf {
    match std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .or_else(|_| {
            std::env::var("HOMEDRIVE").and_then(|homedrive| {
                std::env::var("HOMEPATH").map(|homepath| format!("{}{}", homedrive, homepath))
            })
        }) {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => panic!("Failed to get home directory"),
    }
}

pub fn get_config_dir() -> std::path::PathBuf {
    let home_dir = get_home_dir();
    home_dir.join(".config/metaphrase")
}

pub fn get_local_dir() -> std::path::PathBuf {
    let home_dir = get_home_dir();
    home_dir.join(".local/metaphrase")
}

pub fn setup() {
    let now = match DEBUG {
        true => "debug".to_string(),
        false => chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string(),
    };

    match std::env::var("OPENAI_API_KEY") {
        Ok(_) => (),
        Err(_) => panic!("OPENAI_API_KEY environment variable not set"),
    }

    let config_path = get_config_dir();
    let local_path = get_local_dir();
    let annotations_path = local_path.join("annotations");
    let logging_path = local_path.join("logs");

    create_if_nonexistent(&config_path);
    create_if_nonexistent(&local_path);
    create_if_nonexistent(&annotations_path);
    create_if_nonexistent(&logging_path);

    crate::logger::Logger::init(format!(
        "{}/{}.log",
        logging_path.to_str().unwrap(),
        now.clone()
    ));

    touch_file(&local_path.join("ledger"));
    touch_file(&config_path.join("ledger"));
}

fn is_whitelisted(path: &str) -> bool {
    for ext in WHITELIST {
        if path.ends_with(format!(".{}", ext).as_str()) {
            return true;
        }
    }

    false
}

fn get_unmarked_files() -> Result<Vec<String>, std::io::Error> {
    let config_path = get_config_dir();
    let config_ledger_path = config_path.join("ledger");

    let config_ledger = match std::fs::File::open(&config_ledger_path) {
        Ok(file) => std::io::BufReader::new(file),
        Err(_) => {
            Logger::info(format!(
                "No ledger found at {:?}, creating one",
                config_ledger_path
            ));
            touch_file(&config_ledger_path);
            std::io::BufReader::new(std::fs::File::open(&config_ledger_path).unwrap())
        }
    };

    let config_ledger = config_ledger
        .lines()
        .map(|line| line.unwrap())
        .collect::<Vec<String>>();

    let mut config_entries = Vec::new();
    for mut entry in config_ledger {
        if entry.starts_with("#") {
            continue;
        }

        let path = std::path::Path::new(&entry);
        if path.is_dir() && (!entry.ends_with("*") || !entry.ends_with("**")) {
            entry.push_str("/**/*");
        }

        info!("searching for files in {}", entry);

        let directory = glob::glob(&entry)
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .collect::<Vec<_>>();

        let mut kept = 0;
        config_entries.extend(
            directory
                .iter()
                .filter(|f| {
                    if is_whitelisted(f.to_str().unwrap()) {
                        kept += 1;
                        return true;
                    } else {
                        return false;
                    }
                })
                .map(|f| f.to_string_lossy().to_string()),
        );

        info!("Kept {} files from {}", kept, entry);
        println!("Kept {} files from {}", kept, entry);
    }

    let local_path = get_local_dir();
    let local_ledger_path = local_path.join("ledger");

    let local_ledger = match std::fs::File::open(&local_ledger_path) {
        Ok(file) => std::io::BufReader::new(file),
        Err(_) => {
            Logger::info(format!(
                "No ledger found at {:?}, creating one",
                local_ledger_path
            ));
            touch_file(&local_ledger_path);
            std::io::BufReader::new(std::fs::File::open(&local_ledger_path).unwrap())
        }
    };

    let local_ledger = local_ledger
        .lines()
        .map(|line| {
            let line = line.unwrap();
            let parts = line
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .collect::<Vec<&str>>();

            parts[0].to_string()
        })
        .collect::<std::collections::HashSet<String>>();

    let new_entries = config_entries
        .iter()
        .filter(|entry| !local_ledger.contains(*entry))
        .map(|entry| entry.to_string())
        .collect::<Vec<String>>();

    Ok(new_entries)
}

fn main() -> Result<(), std::io::Error> {
    setup();
    let entries = get_unmarked_files()?;

    let local_path = get_local_dir();
    let local_ledger_path = local_path.join("ledger");
    let annotations_path = local_path.join("annotations");

    let mut local_ledger = match std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&local_ledger_path)
    {
        Ok(file) => file,
        Err(e) => {
            error!(
                "Failed to open ledger file {}: {}",
                local_ledger_path.to_str().unwrap(),
                e
            );
            return Err(e);
        }
    };

    for i in 0..entries.len() {
        let entry = &entries[i];

        let entry_path = std::path::Path::new(entry);
        let filename = if let Some(filename) = entry_path.file_name() {
            if let Some(filename) = filename.to_str() {
                filename.split('.').collect::<Vec<&str>>()[0].to_string()
            } else {
                chrono::Local::now().timestamp_micros().to_string()
            }
        } else {
            chrono::Local::now().timestamp_micros().to_string()
        };

        let annotation_filename = annotations_path.join(filename.clone());

        let mut annotation_file = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(annotations_path.join(filename))
        {
            Ok(file) => file,
            Err(e) => {
                error!(
                    "Failed to open annotation file {}: {}",
                    annotation_filename.to_str().unwrap(),
                    e
                );
                continue;
            }
        };

        let annotation = openai::annotate(entry.to_string())?;

        match annotation_file.write_all(annotation.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                error!(
                    "Failed to write annotation to file {}: {}",
                    annotation_filename.to_str().unwrap(),
                    e
                );
                continue;
            }
        }

        match local_ledger
            .write_all(format!("{} {}\n", entry, annotation_filename.to_str().unwrap()).as_bytes())
        {
            Ok(_) => (),
            Err(e) => {
                error!(
                    "Failed to write entry to ledger {}: {}",
                    local_ledger_path.to_str().unwrap(),
                    e
                );
                continue;
            }
        }

        info!("added annotation for {} to ledger", entry);
    }

    Ok(())
}
