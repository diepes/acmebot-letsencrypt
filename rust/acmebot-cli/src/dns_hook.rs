//! DNS-01 challenge automation: either shell out to operator-supplied hook commands to
//! set/clear a TXT record, or fall back to an interactive "manual mode" that prints the
//! record and waits for the operator to press Enter (mirroring certbot's manual plugin).

use std::process::Command;

/// Runs `sh -c <command>` with `ACME_TXT_DOMAIN` and `ACME_TXT_VALUE` set in the child
/// environment, returning an error if the command is missing, fails to spawn, or exits
/// non-zero.
fn run_hook(command: &str, txt_domain: &str, txt_value: &str) -> Result<(), String> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("ACME_TXT_DOMAIN", txt_domain)
        .env("ACME_TXT_VALUE", txt_value)
        .status()
        .map_err(|e| format!("failed to run DNS hook command '{command}': {e}"))?;

    if !status.success() {
        return Err(format!(
            "DNS hook command '{command}' exited with status {status}"
        ));
    }

    Ok(())
}

/// Publishes the dns-01 TXT record, either via `set_command` or interactively.
pub fn set_txt_record(
    set_command: Option<&str>,
    txt_domain: &str,
    txt_value: &str,
) -> Result<(), String> {
    match set_command {
        Some(command) => run_hook(command, txt_domain, txt_value),
        None => {
            println!();
            println!("Please create the following DNS TXT record, then press Enter to continue:");
            println!("  Name:  {txt_domain}");
            println!("  Value: {txt_value}");
            println!();
            wait_for_enter()
        }
    }
}

/// Removes the dns-01 TXT record, either via `clear_command` or interactively.
pub fn clear_txt_record(
    clear_command: Option<&str>,
    txt_domain: &str,
    txt_value: &str,
) -> Result<(), String> {
    match clear_command {
        Some(command) => run_hook(command, txt_domain, txt_value),
        None => {
            println!();
            println!("You may now remove the DNS TXT record:");
            println!("  Name:  {txt_domain}");
            println!("  Value: {txt_value}");
            Ok(())
        }
    }
}

fn wait_for_enter() -> Result<(), String> {
    use std::io::Read;

    print!("Press Enter to continue... ");
    std::io::Write::flush(&mut std::io::stdout()).map_err(|e| format!("failed to flush stdout: {e}"))?;

    let mut buf = [0u8; 1];
    // Read until a newline (or EOF) is seen; we don't need the content, just the pause.
    loop {
        match std::io::stdin().read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(_) => {
                if buf[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(format!("failed to read from stdin: {e}")),
        }
    }

    Ok(())
}
