# Chromium Extension Packager

This program helps maintain a list of chromium extensions, check them for update by fetching and parsing
its webstore page, downloading any available updates, and packaging them as Debian packages.

## Usage

Make sure the directory `/var/lib/chromium-extension-packager` exists and is writable by the user
who will be running the script.


```
COMMANDS:
     list     [uuid] print extensions information
     add      <uuid> add an extension to the list
     remove   <uuid> remove an extension from the list
     update   [uuid] update extension(s) package(s)
```
