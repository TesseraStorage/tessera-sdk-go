package siastorage

// Egress reporting (client-asserted byte-count reporting to an indexer
// endpoint) has been removed entirely from this SDK fork per the packet law:
// "No T-SDK may post a read/egress report, ever." There is no option, type,
// or internal hook left anywhere in this package that can build or send such
// a report. This file is kept only as a placeholder; it intentionally
// contains no egress-reporting code.
