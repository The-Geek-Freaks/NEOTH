# W244 native fixture compile repair

The hosted W244 admission stopped before test discovery on two stale `McpServers`
test fixtures that omitted the required `smart_loading` field, plus one unused
`clap::Args` test import. Both fixtures now explicitly use `smart_loading: false`,
matching the default master-off convention for narrow native-codegraph fixtures.

This is a source-only repair under the active BSOD hold. No local Cargo, formatter,
parser, test, or runtime command was run.
