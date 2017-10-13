# Chromium Extension Packager

This program helps maintain a list of chromium extensions, check them for update by fetching and parsing
its webstore page, downloading any available updates, and packaging them as Debian packages.
Once done, it generates a package and source index for using as a local apt repository.

## Building & Installing

A Debian package is provided using git-buildpackage in the [debian branch](https://github.com/subgraph/chromium-extension-packager/tree/debian).

The package provides a cron to check for updates twice a day, and installs the local repository to the apt sources.

## Usage

This program expects to run as `root`, or as `_apt`.

```
COMMANDS:
	list     [uuid] Print extensions information
	add      <uuid> Add an extension to the list
	remove   <uuid> Remove an extension from the list
	update   [uuid] Update extension(s) package(s)
	help, h         Shows a list of commands or help for one command
```
