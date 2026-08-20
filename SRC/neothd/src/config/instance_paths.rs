use std::path::{Path, PathBuf};

/// Files and directories owned by one NEOTH runtime instance.
///
/// `home` is derived from the selected `--config` parent. `config_path` is
/// retained separately because the operator may select a file whose name is
/// not `freedom.yaml`. Runtime callers must use this value instead of falling
/// back to process-global HOME / USERPROFILE paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstancePaths {
    pub(crate) home: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) mcp_servers: PathBuf,
    pub(crate) tweaks: PathBuf,
    pub(crate) ccr: PathBuf,
    pub(crate) adr: PathBuf,
    pub(crate) archive: PathBuf,
    pub(crate) code_map: PathBuf,
    /// Account-scoped context graph store.  This is deliberately instance
    /// local: selecting `--config` must never cross-read another profile.
    pub(crate) context_db: PathBuf,
    pub(crate) profile_extensions: PathBuf,
}

impl InstancePaths {
    /// Resolve every instance-owned path from an explicit home and config.
    pub(crate) fn new(home: impl Into<PathBuf>, config: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            config: config.into(),
            mcp_servers: home.join("mcp_servers.yaml"),
            tweaks: home.join("tweaks.toml"),
            ccr: home.join("ccr"),
            adr: home.join("adr"),
            archive: home.join("archive"),
            code_map: home.join("code_map.db"),
            context_db: home.join("context.db"),
            profile_extensions: home.join("profile_extensions.toml"),
            home,
        }
    }

    /// Resolve paths for callers whose canonical config is `freedom.yaml`.
    pub(crate) fn for_home(home: impl AsRef<Path>) -> Self {
        let home = home.as_ref().to_path_buf();
        Self::new(home.clone(), home.join("freedom.yaml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_instance_paths_never_fall_back_to_process_home() {
        let home = PathBuf::from("isolated/operator-a");
        let config = home.join("custom-policy.yaml");
        let paths = InstancePaths::new(&home, &config);

        assert_eq!(paths.home, home);
        assert_eq!(paths.config, config);
        assert_eq!(paths.mcp_servers, home.join("mcp_servers.yaml"));
        assert_eq!(paths.tweaks, home.join("tweaks.toml"));
        assert_eq!(paths.ccr, home.join("ccr"));
        assert_eq!(paths.adr, home.join("adr"));
        assert_eq!(paths.archive, home.join("archive"));
        assert_eq!(paths.code_map, home.join("code_map.db"));
        assert_eq!(paths.context_db, home.join("context.db"));
        assert_eq!(
            paths.profile_extensions,
            home.join("profile_extensions.toml")
        );
    }

    #[test]
    fn default_instance_config_is_scoped_to_the_explicit_home() {
        let home = PathBuf::from("isolated/operator-b");
        let paths = InstancePaths::for_home(&home);

        assert_eq!(paths.config, home.join("freedom.yaml"));
        assert!(
            [
                &paths.mcp_servers,
                &paths.tweaks,
                &paths.ccr,
                &paths.adr,
                &paths.archive,
                &paths.code_map,
                &paths.context_db,
                &paths.profile_extensions,
            ]
            .into_iter()
            .all(|path| path.starts_with(&home))
        );
    }
}
