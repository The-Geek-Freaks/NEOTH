//! External knowledge sources NEOTH ingests for self-reflection.
//!
//! Currently: [`hackernews`] — Hacker News as a "tech-currency" feed feeding
//! the self-reflect gap pass (am I still current? what do my skills not cover?).
//! Adapters here are pure fetch + deterministic analysis; the operator-facing
//! surface is `neoth reflect` ([`crate::cli::reflect`]).

pub mod hackernews;
