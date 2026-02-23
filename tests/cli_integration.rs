/// End-to-end CLI integration tests
#[path = "cli/common.rs"]
mod common;
#[path = "cli/help_tests.rs"]
mod help_tests;
#[path = "cli/error_tests.rs"]
mod error_tests;
#[path = "cli/output_tests.rs"]
mod output_tests;
#[path = "cli/run_tests.rs"]
mod run_tests;
#[path = "cli/inspect_tests.rs"]
mod inspect_tests;
