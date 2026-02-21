# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deprecated
- `--contract-path` renamed to `--contract` (with backward compatibility)
- `--fn` renamed to `--function` (with backward compatibility)
- `--params` renamed to `--args` (with backward compatibility)
- `--snapshot` renamed to `--network-snapshot` (with backward compatibility)

## [0.1.0] - 2026-02-19

### Added

- Step-through execution of Soroban contracts
- Breakpoints at function boundaries
- Contract storage and state inspection
- CPU and memory budget tracking
- Call stack viewing for contract invocations
- Interactive terminal UI for debugging sessions
- Cross-contract call support
- Basic test coverage
- Contribution guidelines

[Unreleased]: https://github.com/Timi16/soroban-debugger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Timi16/soroban-debugger/releases/tag/v0.1.0
