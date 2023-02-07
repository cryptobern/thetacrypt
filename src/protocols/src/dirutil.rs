use std::fs::{create_dir, remove_file, File};
use std::path::PathBuf;

use log::debug;

/// Ensure the given directory exists, creating it if it does not.
///
/// If either the checking or creation fails, an error is returned.
pub fn ensure_directory_exists(dir: &PathBuf) -> Result<(), String> {
    debug!("Ensuring that directory exists");

    let exists = match dir.try_exists() {
        Ok(b) => b,
        Err(e) => {
            return Err(format!(
                "Error checking existence of output directory: {}",
                e
            ));
        }
    };

    if !exists {
        match create_dir(dir) {
            Ok(_) => debug!("Created output directory"),
            Err(e) => {
                return Err(format!("Error creating output directory: {}", e));
            }
        }
    }

    Ok(())
}

/// Ensures if the given directory is empty.
///
/// Returns an error if checking fails, or it is not empty.
pub fn ensure_directory_is_empty(dir: &PathBuf) -> Result<(), String> {
    debug!("Ensuring that output directory is empty");

    let mut dir_entries = match dir.read_dir() {
        Ok(d) => d,
        Err(e) => {
            return Err(format!(
                "Error checking contents of output directory: {}",
                e
            ));
        }
    };

    let is_empty = dir_entries.next().is_none();
    if !is_empty {
        return Err(format!("Output directory is not empty"));
    }

    Ok(())
}

pub fn ensure_directory_is_writeable(dir: &PathBuf) -> Result<(), String> {
    debug!("Ensuring that directory is writeable");

    let mut test_file = dir.clone();
    test_file.push("foo");
    match File::create(&test_file) {
        Ok(_) => debug!("Successfully created file in output directory"),
        Err(e) => {
            return Err(format!("Unable to write file to output directory: {}", e));
        }
    };

    match remove_file(test_file) {
        Ok(_) => debug!("Successfully removed file in output directory"),
        Err(e) => {
            return Err(format!(
                "Unable to remove test file in output directory: {}",
                e
            ));
        }
    }

    Ok(())
}

/// Checks if the given directory is suitable to write the keygen's output to.
///
/// This ensures that:
/// - The directory exists
/// - The directory is empty
/// - The directory is writeable
///
/// Returns an error message describing why the directory is not suitable, in case of failure.
pub fn ensure_sane_output_directory(dir: &PathBuf, require_empty: bool) -> Result<(), String> {
    debug!("Checking output directory: {}", dir.display());

    ensure_directory_exists(dir)?;
    if require_empty {
        ensure_directory_is_empty(dir)?;
    }
    ensure_directory_is_writeable(dir)?;

    Ok(())
}
