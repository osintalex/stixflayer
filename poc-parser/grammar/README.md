# STIX Pattern grammar

`STIXPattern.g4` is the unmodified OASIS grammar, fetched on 2026-11-18 from:

    https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/pattern_grammar/STIXPattern.g4

SHA-256:

    bfe2cd1367705630783c55fb1f9969feb94ed43e27acd0c266e6bc0846f761c1

It is 237 lines, a single combined grammar, with no embedded actions, no semantic predicates, and no
lexer modes. `antlr-poc` feeds this file to the generator unmodified; the other PoCs port it by hand.

STIX 2.1 (10 June 2021) is still the current standard: there is no 2.2 document at
`docs.oasis-open.org/cti/stix/v2.2/`, and `cti-stix2-json-schemas` has only `master`, `stix2.0`, and
`stix2.1` branches.
