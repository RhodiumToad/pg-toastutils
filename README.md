
pg_toastutils
=============

Diagnostic utilities for TOASTed data values in PostgreSQL.

WARNING
=======

**This is experimental code, and may break, crash, destroy your
database, whatever.**

Contents
--------

    is_toasted("any") returns boolean
    is_external("any") returns boolean
    toast_type("any") returns toast_type_enum
    toast_ptr_detail(IN "any") returns record
    toast_item_detail(IN "any") returns record
    toast_validate_table(tableoid regclass, verbose boolean) returns setof record

Author
------

Andrew Gierth, aka RhodiumToad

License: PostgreSQL License
