# Overview

Create library code that writes and validates STIX data in Rust but can run in Python, JavaScript/TypeScript,
Go, and Java.

## Design

To achieve this, we will use the existing oasis repository that this repo is forked off. This is an official 
library implementation for working with STIX in Rust.

Then we will do the following for each language. Core design principle is that for every language, the user can just
zero config install the package and run it, i.e. `pip install <package>` is all they need. No external dependencies
are required.

### Python

Use Pyo3 to expose the Rust code in Python.

### JavaScript/TypeScript

Use the equivalent of Pyo3 in node (I can't remember the name) to expose the Rust code in TypeScript.

### Java

Use extism to compile to WASM and then use the zero config wasm engine in Java to run the code. I can't remember
what this is called but it might be chicory. The point is - I do not want to ever require some extism package to
be installed.

### Go

Basically exactly the same as Java. I just can't remember the name of the WASM engine again.

## Approach

For every language we will use a TDD approach, i.e. begin by writing a test suite to define the behaviour we want.
Then once the user has manually approved that, we will write the per-language implementation and keep testing it until
it meets the test suite.
