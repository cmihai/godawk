# godawk

Converts "go doc" output to Markdown. The script is dead simple; all it does is add
code blocks and headings (which Github should automatically generate a table of
contents from).

## Usage

Put the script somewhere in `$PATH` and run it like this:

```
go doc -all yourpackage | doc2mark.awk > APIDOC.md 
```

The script expects the "go doc" output to have sections, so the `-all` flag is required.

See examples of generated markup in the appropriately-named [examples](./examples) dir.
