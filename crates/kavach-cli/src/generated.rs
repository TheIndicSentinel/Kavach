//! `kavach completions <shell>` and `kavach man`: shell completions and man
//! pages generated from the command tree itself, so they cannot drift from
//! it. They go through the same (redacting) output as everything else; a
//! test checks that leaves them byte for byte as generated.

use std::path::Path;

use clap_complete::Shell;
use serde_json::json;

use crate::output::{CliError, Status, Ui};

/// The completion script for `shell`.
pub fn completion_script(shell: Shell, command: &mut clap::Command) -> Result<String, CliError> {
    let mut script = Vec::new();
    clap_complete::generate(shell, command, "kavach", &mut script);
    String::from_utf8(script).map_err(|e| CliError::new("the completion script is not UTF-8", e))
}

pub fn completions(ui: Ui, shell: Shell, mut command: clap::Command) -> Result<i32, CliError> {
    let script = completion_script(shell, &mut command)?;
    let data = json!({ "shell": shell.to_string(), "script": script });
    Ok(ui.finish("completions", Status::Ok, &data, script.trim_end()))
}

/// The `kavach(1)` page, in roff.
pub fn man_page(command: clap::Command) -> Result<String, CliError> {
    let mut page = Vec::new();
    clap_mangen::Man::new(command)
        .render(&mut page)
        .map_err(|e| CliError::new("cannot render the man page", e))?;
    String::from_utf8(page).map_err(|e| CliError::new("the man page is not UTF-8", e))
}

/// `kavach man`: `kavach(1)` on stdout, or with `--out`, one page per
/// command (`kavach.1`, `kavach-dev-up.1`, …) written to that directory.
pub fn man(ui: Ui, command: clap::Command, out: Option<&Path>) -> Result<i32, CliError> {
    let Some(out) = out else {
        let page = man_page(command)?;
        let data = json!({ "page": "kavach.1", "roff": page });
        return Ok(ui.finish("man", Status::Ok, &data, page.trim_end()));
    };
    std::fs::create_dir_all(out)
        .map_err(|e| CliError::new(format!("cannot create {}", out.display()), e))?;
    clap_mangen::generate_to(command, out).map_err(|e| {
        CliError::new(
            format!("cannot write the man pages to {}", out.display()),
            e,
        )
    })?;
    let mut pages: Vec<String> = std::fs::read_dir(out)
        .map_err(|e| CliError::new(format!("cannot read {}", out.display()), e))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("kavach") && name.ends_with(".1"))
        .collect();
    pages.sort();
    let human = format!(
        "wrote {} man pages to {}\nRead one with: man {}/kavach.1",
        pages.len(),
        out.display(),
        out.display()
    );
    let data = json!({ "dir": out.display().to_string(), "pages": pages });
    Ok(ui.finish("man", Status::Ok, &data, &human))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_leaves_completions_and_man_pages_as_generated() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let script = completion_script(shell, &mut crate::command()).unwrap();
            assert!(script.contains("kavach"), "{shell}");
            // What is printed: trimmed, then one newline.
            let printed = script.trim_end();
            assert_eq!(crate::output::redact(printed), printed, "{shell}");
        }
        let page = man_page(crate::command()).unwrap();
        assert!(page.contains(".TH kavach"), "{page}");
        assert_eq!(crate::output::redact(page.trim_end()), page.trim_end());
    }

    #[test]
    fn every_command_gets_a_man_page() {
        let dir = std::env::temp_dir().join(format!("kavach-man-{}", uuid::Uuid::new_v4()));
        man(Ui::new(true), crate::command(), Some(&dir)).unwrap();
        for page in [
            "kavach.1",
            "kavach-dev-up.1",
            "kavach-why.1",
            "kavach-policy-test.1",
        ] {
            assert!(dir.join(page).is_file(), "{page}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
