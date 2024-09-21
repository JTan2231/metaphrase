use std::io::Write;
use std::sync::Once;

pub struct Logger {
    file: std::fs::File,
}

static mut INSTANCE: Option<Logger> = None;
static INIT: Once = Once::new();

#[cfg(feature = "stdout")]
pub const USE_STDOUT: bool = true;
#[cfg(not(feature = "stdout"))]
pub const USE_STDOUT: bool = false;

impl Logger {
    pub fn init(filename: String) -> &'static Logger {
        unsafe {
            INIT.call_once(|| {
                INSTANCE = Some(Logger {
                    file: std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(filename)
                        .expect("Failed to open log file"),
                });
            });

            INSTANCE.as_ref().unwrap()
        }
    }

    #[allow(dead_code)]
    pub fn info(message: String) {
        unsafe {
            if INSTANCE.is_none() {
                panic!("Logger not initialized");
            }

            let mut file = INSTANCE
                .as_ref()
                .unwrap()
                .file
                .try_clone()
                .expect("Failed to clone file");

            let message = format!("{} [INFO]: {}", chrono::Local::now(), message);
            writeln!(file, "{}", message).expect("Failed to write to log file");

            if USE_STDOUT {
                println!("{}", message);
            }
        }
    }

    pub fn error(message: String) {
        unsafe {
            if INSTANCE.is_none() {
                panic!("Logger not initialized");
            }

            let mut file = INSTANCE
                .as_ref()
                .unwrap()
                .file
                .try_clone()
                .expect("Failed to clone file");

            let message = format!("{} [ERROR]: {}", chrono::Local::now(), message);
            writeln!(file, "{}", message).expect("Failed to write to log file");

            if USE_STDOUT {
                println!("{}", message);
            }
        }
    }
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        Logger::info(format!($($arg)*));
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        Logger::error(format!($($arg)*));
    }
}