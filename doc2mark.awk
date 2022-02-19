#!/usr/bin/awk -f

/^package [a-z]+ \/\/ import / {
	printf "# %s %s\n\n", $1, $2
	printf "```golang\n%s\n```\n", $0
	state = "PLAIN_TEXT"
	next
}

/^(FUNCTIONS|TYPES|CONSTANTS|VARIABLES)$/ {
	print "##", $0
	section = $0
	next
}

# Type constructor, or regular function
/^func [A-Z][A-Za-z0-9_]+\(/ {
	split($0, a, "(")
	if (section == "FUNCTIONS") {
		print "###", a[1], "\n"
	} else {
		print "####", a[1], "\n"
	}
	print "```golang"
	print $0

	if (index($0, "(") == length($0)) {
		state = "PAREN_BLOCK"
	} else {
		print "```\n"
		state = "INDENTED_TEXT"
	}
	next
}

# Type method (named type variable)
/^func \([^\) ]+ [^\)]+\) [^\(]+\(/ {
	split($4, a, "(")

	printf "#### func (%s) %s\n\n", substr($2, 2), a[1]
	print "```golang"
	print $0

	if (index($0, "(") == length($0)) {
		state = "PAREN_BLOCK"
	} else {
		print "```\n"
		state = "INDENTED_TEXT"
	}
	next
}

# Type method (anonymous type variable)
/^func \([^\)]+\) [^\(]+\(/ {
	split($3, a, "(")
	print "#### func", a[1], "\n"
	print "```golang"
	print $0

	if (index($0, "(") == length($0)) {
		state = "PAREN_BLOCK"
	} else {
		print "```\n"
		state = "INDENTED_TEXT"
	}
	next
}

/^type [A-Z][A-Za-z0-9_]+ / {
	print "###", $1, $2, "\n"
	print "```golang"
	print $0

	if (index($0, "{") == length($0)) {
		state = "CURLY_BLOCK"
	} else {
		print "```\n"
		state = "INDENTED_TEXT"
	}
	next
}

/^(const|var) / {
	print "```golang"
	print $0
	if (index($0, "(") == length($0)) {
		state = "PAREN_BLOCK"
	} else {
		print "```\n"
		state = "INDENTED_TEXT"
	}
	next
}

# Unindented (e.g. package-level) docstring
state == "PLAIN_TEXT" {
	print sanitize($0)
}

# Indented docstring
state == "INDENTED_TEXT" {
	sub(/^    /, "")
	print sanitize($0)
}

# Multi-line function header, or const or variable block 
state == "PAREN_BLOCK" {
	print

	if (index($0, ")") == 1) {
		print "```\n"
		state = "INDENTED_TEXT"
	}
}

# Type definition
state == "CURLY_BLOCK" {
	print

	if (index($0, "}") == 1) {
		print "```\n"
		state = "INDENTED_TEXT"
	}
}

function sanitize(row) {
	if (match(row, /^    /) == 0) {
		gsub(/_/, "\\_", row)
		gsub(/\*/, "\\*", row)
	}
	return row
}
