# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Argument `--backend` for specifying if using Nftables or legacy Ipset.
- Argument `--cache-dir` for specifying a directory path where certificates
  are to be stored.
- Argument `--table` to set the table name in Nftables.
- Argument `--syslog` explicitly redirects log messages to Syslog.
- Configuration for the Systemd service is now read from `/etc/default/sentinel-dynfw-client`.
- Send heartbeats to the ZMQ server once per minute, enabling the ZMQ library to
  automatically reconnect if a reply is not received in time. This fixes a "stuck client"
  in case the connection is abruptly lost, as the ZMQ socket would still be connected.
- Support Systemd notifications.

### Changed

- General code refactor and update.
- The Systemd service file has been updated according to code changes, and a certain
  number of security options has been added.
- The Systemd service reads configuration parameters from `/etc/default/sentinel-dynfw-client`.
  Default values are provided.
- Enable dual stack support when connecting to the Sentinel server, so that the connection
  goes over IPv6 if IPv6 connectivity is available.

### Removed

- Argument `--cert`  and `--renew` have been removed and the server certificate
  is always downloaded on start.

## [1.4.0] - 2020-08-06

### Added

- Argument `--renew` that automatically receives latest version of server
  certificate on client startup
- Argument `--cert-url` to specify URL used to get server's certificate when
  `--renew` is used

## [1.3.1] - 2020-06-09

### Added

- Filter for IPv4 addresses (invalid ones are dropped)

## [1.3] - 2020-05-04

### Added

- Changelog

### Changed

- Default server certificate path
- Location of temporary run directory (for client key and certificate)
- Fix temporary run directory permissions
- Fix logger deprecation warnings

## [1.2.1] - 2020-05-03

### Added

- `--verbose` command-line argument

### Changed

- Default logging severity to *info*

## [1.2] - 2020-04-24

### Added

- Compatibility with msgpack >= 1.0

### Changed

- Fixed tier-down of monitor socket
- Update documentation and license
- Improve error messages

## [1.1.2] - 2020-04-16

### Changed

- Default location of public key

## [1.1.1] - 2020-01-24

### Changed

- Add support files for distribution

## [1.1] - 2019-11-21

### Changed

- `--ipset` command-line argument
- License file

## [1.0] - 2017-07-17

### Changed

- Initial release
- Prototype moved from DynFW repository
- Refactoring

### Added
- Monitor socket to detect handshake failures
