# Chromium Extension Packager

This program helps maintain a list of chromium extensions, check them for update by fetching and parsing
its webstore page, downloading any available updates, and packaging them as Debian packages.
Once done, it generates a package and source index for using as a local apt repository.

## Building

Debian Package TBD...

## Usage

Make sure the directory `/var/lib/chromium-extension-packager` exists and is writable by the user
who will be running the script.


```
COMMANDS:
	list     [uuid] Print extensions information
	add      <uuid> Add an extension to the list
	remove   <uuid> Remove an extension from the list
	update   [uuid] Update extension(s) package(s)
	help, h         Shows a list of commands or help for one command
```
