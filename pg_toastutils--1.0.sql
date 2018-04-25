-- pg_toastutils extension

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_toastutils" to load this file. \quit

CREATE TYPE toast_type_enum AS ENUM ('short',
                                     'compressed',
				     'indirect',
				     'expanded_ro',
				     'expanded_rw',
				     'external',
				     'external_compressed',
				     'unknown');

CREATE FUNCTION is_toasted("any") RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE;
CREATE FUNCTION is_external("any") RETURNS boolean AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE;
CREATE FUNCTION toast_type("any") RETURNS toast_type_enum AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION toast_ptr_detail(IN ptr "any",
       				 OUT is_toast boolean,
				 OUT is_external boolean,
				 OUT is_compressed boolean,
				 OUT toast_type toast_type_enum,
				 OUT rawsize integer,
				 OUT extsize integer,
				 OUT valueid oid,
				 OUT toastrelid oid) AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE;

CREATE FUNCTION toast_item_detail(IN ptr "any",
                                  OUT is_toast boolean,
				  OUT is_external boolean,
				  OUT valid boolean,
				  OUT error text,
				  OUT xmin xid,
				  OUT xmax xid) AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE;

CREATE FUNCTION toast_validate_table(IN tableoid regclass,
       				     IN verbose boolean)
  RETURNS TABLE(row_ctid tid,
  	  	row_live boolean,
	 	row_xmin xid,
	 	row_xmax xid,
	 	column_name name,
		toast_oid oid,
	 	toast_xmin xid,
	 	toast_xmax xid,
	 	error text)
  AS 'MODULE_PATHNAME' LANGUAGE C VOLATILE STRICT;

-- end
