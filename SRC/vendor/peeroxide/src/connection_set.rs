use std::collections::HashMap;

pub(crate) struct ConnectionInfo {
    /// Identifies one concrete connection lifetime for this public key.
    ///
    /// A close notification may arrive after a replacement connection was
    /// registered for the same key, so removal must match this id as well as
    /// the key.
    pub registration_id: u64,
}

pub(crate) struct ConnectionSet {
    by_public_key: HashMap<[u8; 32], ConnectionInfo>,
}

impl ConnectionSet {
    pub fn new() -> Self {
        Self {
            by_public_key: HashMap::new(),
        }
    }

    pub fn has(&self, public_key: &[u8; 32]) -> bool {
        self.by_public_key.contains_key(public_key)
    }

    #[cfg(test)]
    pub fn get(&self, public_key: &[u8; 32]) -> Option<&ConnectionInfo> {
        self.by_public_key.get(public_key)
    }

    pub fn add(&mut self, public_key: [u8; 32], info: ConnectionInfo) {
        self.by_public_key.insert(public_key, info);
    }

    #[cfg(test)]
    pub fn remove(&mut self, public_key: &[u8; 32]) -> bool {
        self.by_public_key.remove(public_key).is_some()
    }

    /// Remove a connection only when the close belongs to the currently
    /// registered lifetime for this public key.
    pub fn remove_if_matches(&mut self, public_key: &[u8; 32], registration_id: u64) -> bool {
        let matches = self
            .by_public_key
            .get(public_key)
            .is_some_and(|info| info.registration_id == registration_id);
        if matches {
            self.by_public_key.remove(public_key);
        }
        matches
    }

    pub fn len(&self) -> usize {
        self.by_public_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_has() {
        let mut set = ConnectionSet::new();
        let pk = [1u8; 32];
        assert!(!set.has(&pk));
        set.add(pk, ConnectionInfo { registration_id: 1 });
        assert!(set.has(&pk));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn remove() {
        let mut set = ConnectionSet::new();
        let pk = [2u8; 32];
        set.add(pk, ConnectionInfo { registration_id: 1 });
        assert!(set.remove(&pk));
        assert!(!set.has(&pk));
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn get_info() {
        let mut set = ConnectionSet::new();
        let pk = [3u8; 32];
        set.add(pk, ConnectionInfo { registration_id: 1 });
        let info = set.get(&pk).expect("should exist");
        assert_eq!(info.registration_id, 1);
    }

    #[test]
    fn stale_close_cannot_remove_replacement_connection() {
        let mut set = ConnectionSet::new();
        let pk = [4u8; 32];
        set.add(
            pk,
            ConnectionInfo {
                registration_id: 10,
            },
        );
        set.add(
            pk,
            ConnectionInfo {
                registration_id: 11,
            },
        );

        assert!(
            !set.remove_if_matches(&pk, 10),
            "a late close for the replaced connection must be ignored"
        );
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(&pk).unwrap().registration_id, 11);
        assert!(set.remove_if_matches(&pk, 11));
        assert_eq!(set.len(), 0);
    }
}
