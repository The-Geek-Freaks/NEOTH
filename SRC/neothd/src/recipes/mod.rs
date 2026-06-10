//! GOLD-ADOPT-16 — declarative, parametrized recipe templates.
//!
//! A recipe is a YAML file with typed [`schema::RecipeParameter`]s and a
//! `{{key}}`-templated prompt. `neoth recipe run <file> --param k=v` substitutes
//! the values and feeds the rendered prompt through the normal `neoth chat`
//! pipeline (skill routing, MCP tool-loop, council, hooks — all for free, since
//! the runner just builds a `ChatArgs` and calls `cli::chat::run_chat`).
//!
//! Ported from goose `crates/goose/src/recipe/`, adapted to NEOTH: hand-rolled
//! `{{key}}` substitution (no template-engine dep — typed params are a finite
//! known set), base64 `neoth://recipe/` deeplink share, and `settings`
//! provider/sampling overrides.
//!
//! Layers:
//! - [`schema`] — the recipe shape + parse + structural validation.
//! - [`render`] — parameter resolution (required/default/type-check) + `{{key}}`
//!   substitution into the concrete prompt/system.
//! - [`deeplink`] — base64 share-link encode/decode.

pub mod deeplink;
pub mod render;
pub mod schema;

pub use render::{render, RenderedRecipe};
pub use schema::{InputType, RecipeError, RecipeParameter, RecipeSettings, RecipeSpec};
