//! `neoth interface` — inspect or change the instance-wide GUI/CLI default.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::interface_preference::{self, InterfacePreference};

#[derive(Args, Clone, Debug)]
pub struct InterfaceArgs {
    #[command(subcommand)]
    pub action: InterfaceAction,
}

#[derive(Clone, Debug, Subcommand)]
pub enum InterfaceAction {
    /// Show whether the one-time GUI/CLI choice has been recorded.
    Show,
    /// Set the default surface used by onboarding and future launchers.
    Set {
        #[arg(value_enum)]
        preferred: InterfaceValue,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InterfaceValue {
    Gui,
    Cli,
}

impl From<InterfaceValue> for InterfacePreference {
    fn from(value: InterfaceValue) -> Self {
        match value {
            InterfaceValue::Gui => Self::Gui,
            InterfaceValue::Cli => Self::Cli,
        }
    }
}

pub fn run_interface(args: InterfaceArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        InterfaceAction::Show => {
            let preferred = interface_preference::load_at(&home)?;
            render(
                preferred,
                &interface_preference::path_at(&home),
                output,
                false,
            );
        }
        InterfaceAction::Set { preferred } => {
            let preferred = InterfacePreference::from(preferred);
            let path = interface_preference::save_at(&home, preferred)?;
            render(Some(preferred), &path, output, true);
        }
    }
    Ok(())
}

fn render(
    preferred: Option<InterfacePreference>,
    path: &std::path::Path,
    output: OutputFormat,
    changed: bool,
) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "chosen": preferred.is_some(),
                "preferred": preferred.map(InterfacePreference::as_str),
                "changed": changed,
                "path": path,
            })
        ),
        OutputFormat::Table => match preferred {
            Some(value) if changed => {
                println!("Default interface set to {value} ({}).", path.display());
            }
            Some(value) => {
                println!("Default interface : {value}");
                println!("Preference file   : {}", path.display());
                println!("Switch anytime    : `neoth gui` or `neoth interface set cli`");
            }
            None => {
                println!("Default interface : not chosen yet");
                println!("Preference file   : {}", path.display());
                println!("Choose explicitly : `neoth interface set gui|cli`");
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_values_map_to_domain_values() {
        assert_eq!(
            InterfacePreference::from(InterfaceValue::Gui),
            InterfacePreference::Gui
        );
        assert_eq!(
            InterfacePreference::from(InterfaceValue::Cli),
            InterfacePreference::Cli
        );
    }
}
