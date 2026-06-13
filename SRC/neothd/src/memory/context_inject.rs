//! GOLD-ADAPT-MEM-06 — knowledge-graph context injection.
//!
//! Formats the BFS neighbours of an entity into a `[RELEVANT FACTS]` block that
//! `neoth recall`'s Stage-3 appends to its output (and that the enrichment
//! pipeline can reuse). Pure — no I/O.

use crate::memory::entities::Neighbor;

/// Banner the facts block leads with.
pub const FACTS_BANNER: &str = "[RELEVANT FACTS]";

/// Render a `[RELEVANT FACTS]` block for `entity` from its graph `neighbors`.
/// Returns the empty string when there are none (nothing to inject).
pub fn build_facts_block(entity: &str, neighbors: &[Neighbor]) -> String {
    if neighbors.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    s.push_str(FACTS_BANNER);
    s.push_str(&format!("\nKnowledge-graph context for \"{entity}\":\n"));
    for n in neighbors {
        let hops = if n.depth == 1 { "1 hop" } else { "2+ hops" };
        s.push_str(&format!("- {} — {} ({hops}, via \"{}\")\n", entity, n.name, n.via_relation));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nb(name: &str, depth: u32, via: &str) -> Neighbor {
        Neighbor {
            id: 1,
            name: name.to_string(),
            depth,
            via_relation: via.to_string(),
        }
    }

    #[test]
    fn empty_neighbors_yield_empty_block() {
        assert_eq!(build_facts_block("Alice", &[]), "");
    }

    #[test]
    fn block_banners_and_lists_each_neighbour() {
        let block = build_facts_block("Alice", &[nb("Mozilla", 1, "works at")]);
        assert!(block.starts_with(FACTS_BANNER));
        assert!(block.contains("Alice"));
        assert!(block.contains("Mozilla"));
        assert!(block.contains("works at"));
        assert!(block.contains("1 hop"));
    }
}
