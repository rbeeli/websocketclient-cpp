# Changelog

All notable changes to this project will be documented in this file.

## [0.3] - 2024-10-13

### Added

- This changelog file
- New `Makefile` with commands `autobahn-docker`, `dev-install`, `test-close`

### Changed

- During tear-down of websocket client, skip SSL and TCP shutdown (directly close) if websocket client is in faulty state.
  This is to prevent the client from hanging/reaching timeout, and is closer to the behaviour the RFC spec mandates.
- Added parameter `bool fail_connection` to socket API `close` and `shutdown` methods.
  The parameter should be set to `true` if the client and/or connection is in a faulty state.
  On shutdown/close, the client will skip SSL and TCP shutdown and directly close the connection since it's likely that the peer will not respond.
- Removed `dev_install.sh` script (moved to `Makefile`)
- Better error message printing in examples
- Log alert `close_notify` in `OpenSslSocket` as warning instead of error

### Fixed

- `to_string` for `ws_client::close_code` also maps `not_set`
