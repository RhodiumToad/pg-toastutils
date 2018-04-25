/*-------------------------------------------------------------------------
 *
 * TOAST utilities
 *
 * Copyright (c) 2016 Andrew Gierth
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose with or without fee is hereby granted, provided that
 * the above copyright notice and this permission notice appear in all
 * copies.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/relscan.h"
#include "access/tuptoaster.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "storage/procarray.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/fmgrprotos.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/typcache.h"
#include "utils/tqual.h"


PG_MODULE_MAGIC;

Datum is_toasted(PG_FUNCTION_ARGS);
Datum is_external(PG_FUNCTION_ARGS);
Datum toast_type(PG_FUNCTION_ARGS);
Datum toast_ptr_detail(PG_FUNCTION_ARGS);
Datum toast_item_detail(PG_FUNCTION_ARGS);
Datum toast_validate_table(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(is_toasted);
PG_FUNCTION_INFO_V1(is_external);
PG_FUNCTION_INFO_V1(toast_type);
PG_FUNCTION_INFO_V1(toast_ptr_detail);
PG_FUNCTION_INFO_V1(toast_item_detail);
PG_FUNCTION_INFO_V1(toast_validate_table);

typedef struct toastutils_typeinfo
{
	Oid		typeid;
	int16	typlen;
	Oid		rettype;
	TupleDesc tupdesc;
} toastutils_typeinfo;

static toastutils_typeinfo *
init_typeinfo(FunctionCallInfo fcinfo, bool is_composite)
{
	toastutils_typeinfo *info = NULL;
	FmgrInfo *flinfo = fcinfo->flinfo;
	Oid typeid;

	Assert(flinfo);

	info = (toastutils_typeinfo *) flinfo->fn_extra;
	typeid = get_fn_expr_argtype(flinfo, 0);
	Assert(OidIsValid(typeid));

	if (!info)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(flinfo->fn_mcxt);
		info = palloc(sizeof(toastutils_typeinfo));
		info->typeid = InvalidOid;
		info->rettype = InvalidOid;
		info->tupdesc = NULL;
		if (is_composite)
		{
			if (get_call_result_type(fcinfo, &info->rettype, &info->tupdesc) != TYPEFUNC_COMPOSITE)
				elog(ERROR, "failed to determine composite return type");
		}
		flinfo->fn_extra = info;
		MemoryContextSwitchTo(oldcontext);
	}

	if (typeid != info->typeid)
	{
		info->typeid = typeid;
		info->typlen = get_typlen(typeid);
		if (!is_composite)
			info->rettype = get_fn_expr_rettype(flinfo);
	}

	return info;
}

/*
 * is_toasted(any)
 *
 * Anything that's not NULL, a fixed-length value, or a plain varlena
 * is considered toasted - including short varlenas.
 */
Datum
is_toasted(PG_FUNCTION_ARGS)
{
	toastutils_typeinfo *info = init_typeinfo(fcinfo, false);
	int16 typlen = info->typlen;
	Datum val = PG_GETARG_DATUM(0);

	if (typlen == -1 && !PG_ARGISNULL(0) && VARATT_IS_EXTENDED(val))
		PG_RETURN_BOOL(true);
	PG_RETURN_BOOL(false);
}

/*
 * is_external(any)
 *
 * Anything that isn't a self-contained value is considered external; that
 * includes expanded objects and indirect toasts as well as on-disk external
 * toasts.
 */
Datum
is_external(PG_FUNCTION_ARGS)
{
	toastutils_typeinfo *info = init_typeinfo(fcinfo, false);
	int16 typlen = info->typlen;
	Datum val = PG_GETARG_DATUM(0);

	if (typlen == -1 && !PG_ARGISNULL(0) && VARATT_IS_EXTERNAL(val))
		PG_RETURN_BOOL(true);
	PG_RETURN_BOOL(false);
}

/*
 * helper function
 */
static Datum
toast_type_internal(Datum val, Oid rettype)
{
	const char *retval = NULL;
	Datum		ret;

	/*
	 * "external" values are also "short", so test externality first.
	 */
	if (VARATT_IS_EXTERNAL(val))
	{
		if (VARATT_IS_EXTERNAL_ONDISK(val))
		{
			varatt_external toast_pointer;
			VARATT_EXTERNAL_GET_POINTER(toast_pointer, val);
			if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
				retval = "external_compressed";
			else
				retval = "external";
		}
		else if (VARATT_IS_EXTERNAL_INDIRECT(val))
			retval = "indirect";
		else if (VARATT_IS_EXTERNAL_EXPANDED_RW(val))
			retval = "expanded_rw";
		else if (VARATT_IS_EXTERNAL_EXPANDED_RO(val))
			retval = "expanded_ro";
		else
			retval = "unknown";
	}
	else if (VARATT_IS_COMPRESSED(val))
		retval = "compressed";
	else if (VARATT_IS_SHORT(val))
		retval = "short";
	else
		retval = "unknown";

	ret = DirectFunctionCall2(enum_in,
							  CStringGetDatum(retval),
							  ObjectIdGetDatum(rettype));
	return ret;
}

/*
 * toast_type(any)
 *
 * Classify the kind of toasted item we have (returns NULL if the item is not
 * toasted, otherwise an enum label)
 */
Datum
toast_type(PG_FUNCTION_ARGS)
{
	toastutils_typeinfo *info = init_typeinfo(fcinfo, false);
	int16 typlen = info->typlen;
	Datum val = PG_GETARG_DATUM(0);
	Datum ret;

	if (typlen != -1 || !VARATT_IS_EXTENDED(val))
		PG_RETURN_NULL();

	ret = toast_type_internal(val, info->rettype);

	PG_RETURN_DATUM(ret);
}


/*
 * toast_ptr_detail
 *
 *	OUT is_toast boolean,
 *	OUT is_external boolean,
 *	OUT is_compressed boolean,
 *	OUT toast_type toast_type_enum,
 *	OUT rawsize integer,
 *	OUT extsize integer,
 *	OUT valueid oid,
 *	OUT toastrelid oid
 */
Datum
toast_ptr_detail(PG_FUNCTION_ARGS)
{
	toastutils_typeinfo *info = init_typeinfo(fcinfo, true);
	int16 typlen = info->typlen;
	Datum val = PG_GETARG_DATUM(0);
	Datum values[8];
	bool isnull[8];
	HeapTuple rettup;
	int i;

	if (info->tupdesc->natts != 8)
		elog(ERROR, "return value mismatch, expected %d atts got %d", 8, info->tupdesc->natts);

	for (i = 0; i < 8; ++i)
	{
		values[i] = (Datum) 0;
		isnull[i] = (i > 0);
	}

	if (typlen != -1 || PG_ARGISNULL(0) || !VARATT_IS_EXTENDED(val))
	{
		values[0] = BoolGetDatum(false);
	}
	else
	{
		values[0] = BoolGetDatum(true);
		isnull[1] = false;
		isnull[3] = false;

		values[3] = toast_type_internal(val, TupleDescAttr(info->tupdesc, 3)->atttypid);

		if (VARATT_IS_EXTERNAL_ONDISK(val))
		{
			varatt_external toast_pointer;
			VARATT_EXTERNAL_GET_POINTER(toast_pointer, val);

			isnull[2] = false;

			values[1] = true;
			values[2] = BoolGetDatum(VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer) ? true : false);

			isnull[4] = false;
			isnull[5] = false;
			isnull[6] = false;
			isnull[7] = false;
			values[4] = Int32GetDatum(toast_pointer.va_rawsize);
			values[5] = Int32GetDatum(toast_pointer.va_extsize);
			values[6] = ObjectIdGetDatum(toast_pointer.va_valueid);
			values[7] = ObjectIdGetDatum(toast_pointer.va_toastrelid);
		}
		else if (VARATT_IS_EXTERNAL(val))
		{
			values[1] = true;
		}
		else
		{
			isnull[2] = false;

			values[1] = false;
			values[2] = BoolGetDatum(VARATT_IS_COMPRESSED(val) ? true : false);
		}
	}

	rettup = heap_form_tuple(info->tupdesc, values, isnull);

	PG_RETURN_HEAPTUPLEHEADER(rettup->t_data);
}


static int toast_open_indexes(Relation toastrel,
							  LOCKMODE lock,
							  Relation **toastidxs,
							  int *num_indexes);
static void toast_close_indexes(Relation *toastidxs, int num_indexes, LOCKMODE lock);
static void init_toast_snapshot(Snapshot toast_snapshot);


static bool
toast_ptr_validate(varatt_external *toast_pointer,
				   const char **error_p,
				   TransactionId *xmin_p,
				   TransactionId *xmax_p,
				   int liveness_count,
				   TransactionId *oldestXmin,
				   HTSV_Result *liveness)
{
	Relation	toastrel;
	Relation   *toastidxs;
	ScanKeyData toastkey;
	SysScanDesc toastscan;
	HeapTuple	ttup;
	TupleDesc	toasttupDesc;
	int32		ressize;
	int32		residx,
				nextidx;
	int32		numchunks;
	Pointer		chunk;
	bool		isnull;
	int32		chunksize;
	int			num_indexes;
	int			validIndex;
	SnapshotData SnapshotToast;
	bool		expect_compressed;
	const char *err = NULL;
	TransactionId xmin = InvalidTransactionId;
	TransactionId xmax = InvalidTransactionId;

	ressize = toast_pointer->va_extsize;
	numchunks = ((ressize - 1) / TOAST_MAX_CHUNK_SIZE) + 1;
	expect_compressed = VARATT_EXTERNAL_IS_COMPRESSED(*toast_pointer);

	/*
	 * Open the toast relation and its indexes
	 */
	toastrel = heap_open(toast_pointer->va_toastrelid, AccessShareLock);
	toasttupDesc = toastrel->rd_att;

	/* Look for the valid index of the toast relation */
	validIndex = toast_open_indexes(toastrel,
									AccessShareLock,
									&toastidxs,
									&num_indexes);

	/*
	 * Setup a scan key to fetch from the index by va_valueid
	 */
	ScanKeyInit(&toastkey,
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toast_pointer->va_valueid));

	/*
	 * Read the chunks by index
	 *
	 * Note that because the index is actually on (valueid, chunkidx) we will
	 * see the chunks in chunkidx order, even though we didn't explicitly ask
	 * for it.
	 */
	nextidx = 0;

	init_toast_snapshot(&SnapshotToast);
	toastscan = systable_beginscan_ordered(toastrel, toastidxs[validIndex],
										   &SnapshotToast, 1, &toastkey);
	while ((ttup = systable_getnext_ordered(toastscan, ForwardScanDirection)) != NULL)
	{
		/*
		 * Have a chunk, extract the sequence number and the data
		 */
		residx = DatumGetInt32(fastgetattr(ttup, 2, toasttupDesc, &isnull));
		Assert(!isnull);
		chunk = DatumGetPointer(fastgetattr(ttup, 3, toasttupDesc, &isnull));
		Assert(!isnull);
		if (!VARATT_IS_EXTENDED(chunk))
		{
			chunksize = VARSIZE(chunk) - VARHDRSZ;
		}
		else if (VARATT_IS_SHORT(chunk))
		{
			/* could happen due to heap_form_tuple doing its thing */
			chunksize = VARSIZE_SHORT(chunk) - VARHDRSZ_SHORT;
		}
		else
		{
			/* should never happen */
			elog(ERROR, "found toasted toast chunk for toast value %u in %s",
				 toast_pointer->va_valueid,
				 RelationGetRelationName(toastrel));
			chunksize = 0;		/* keep compiler quiet */
		}

		/*
		 * Some checks on the data we've found
		 */
		if (residx != nextidx)
		{
			err = psprintf("unexpected chunk number %d (expected %d)", residx, nextidx);
			break;
		}
		if (residx < numchunks - 1)
		{
			if (chunksize != TOAST_MAX_CHUNK_SIZE)
			{
				err = psprintf("unexpected chunk size %d (expected %d) in chunk %d of %d",
							   chunksize, (int) TOAST_MAX_CHUNK_SIZE, residx, numchunks);
				break;
			}
		}
		if (residx == numchunks - 1)
		{
			if ((residx * TOAST_MAX_CHUNK_SIZE + chunksize) != ressize)
			{
				err = psprintf("unexpected chunk size %d (expected %d) in final chunk %d",
							   chunksize, (int) (ressize - residx * TOAST_MAX_CHUNK_SIZE),
							   residx);
				break;
			}
		}
		if (residx >= numchunks)
		{
			err = psprintf("unexpected chunk number %d (out of range 0..%d)",
						   residx, numchunks - 1);
			break;
		}

		/*
		 * We must check that the compression status (and length, if
		 * compressed) of the value matches that of the pointer. For that, we
		 * examine (only) the first chunk.
		 */
		if (residx == 0)
		{
			if (expect_compressed)
			{
				int32 rawsize;

				if (chunksize < sizeof(int32))
				{
					err = psprintf("compressed initial chunk too small (%d bytes)", chunksize);
					break;
				}

				memcpy(&rawsize, VARDATA_ANY(chunk), sizeof(int32));
				if ((rawsize + VARHDRSZ) != toast_pointer->va_rawsize)
				{
					err = psprintf("inconsistent compressed length: ptr has %d, chunk has %d",
								   toast_pointer->va_rawsize - VARHDRSZ, rawsize);
					break;
				}
			}

			/* let the macro sub in FrozenXid to indicate frozenness */
			xmin = HeapTupleHeaderGetXmin(ttup->t_data);
			/* raw xmax is ok, because toast tuples can't be updated */
			xmax = HeapTupleHeaderGetRawXmax(ttup->t_data);

			if (liveness_count)
			{
				Buffer buf = toastscan->iscan->xs_cbuf;
				int i;

				LockBuffer(buf, BUFFER_LOCK_SHARE);

				for (i = 0; i < liveness_count; ++i)
					liveness[i] = HeapTupleSatisfiesVacuum(ttup, oldestXmin[i], buf);

				LockBuffer(buf, BUFFER_LOCK_UNLOCK);
			}
		}
		else
		{
			TransactionId xid;

			xid = HeapTupleHeaderGetXmin(ttup->t_data);
			if (xid != xmin)
			{
				err = psprintf("inconsistent xmin: chunk 0 had %u, chunk %d has %u",
							   xmin, residx, xid);
				break;
			}
			xid = HeapTupleHeaderGetRawXmax(ttup->t_data);
			if (xid != xmax)
			{
				err = psprintf("inconsistent xmax: chunk 0 had %u, chunk %d has %u",
							   xmin, residx, xid);
				break;
			}
		}

		nextidx++;
	}

	/*
	 * Final checks
	 */
	if (!err && nextidx != numchunks)
		err = psprintf("missing chunk number %d", nextidx);

	/*
	 * End scan and close relations
	 */
	systable_endscan_ordered(toastscan);
	toast_close_indexes(toastidxs, num_indexes, AccessShareLock);
	heap_close(toastrel, AccessShareLock);

	*error_p = err;

	if (!err)
	{
		*xmin_p = xmin;
		*xmax_p = xmax;
	}

	return err == NULL;
}

/*
 * toast_item_detail
 *
 *	OUT is_toast boolean,
 *	OUT is_external boolean,
 *	OUT valid boolean,
 *	OUT error text,
 *	OUT xmin xid,
 *	OUT xmax xid
 */
Datum
toast_item_detail(PG_FUNCTION_ARGS)
{
	toastutils_typeinfo *info = init_typeinfo(fcinfo, true);
	int16 typlen = info->typlen;
	Datum val = PG_GETARG_DATUM(0);
	Datum values[6];
	bool isnull[6];
	HeapTuple rettup;
	int i;

	if (info->tupdesc->natts != 6)
		elog(ERROR, "return value mismatch, expected %d atts got %d", 6, info->tupdesc->natts);

	for (i = 0; i < 6; ++i)
	{
		values[i] = (Datum) 0;
		isnull[i] = (i > 0);
	}

	if (typlen != -1 || PG_ARGISNULL(0) || !VARATT_IS_EXTENDED(val))
	{
		values[0] = BoolGetDatum(false);
	}
	else if (VARATT_IS_EXTERNAL(val) && !VARATT_IS_EXTERNAL_ONDISK(val))
	{
		values[0] = BoolGetDatum(true);
		values[1] = BoolGetDatum(true);
		isnull[1] = false;
	}
	else if (!VARATT_IS_EXTERNAL_ONDISK(val))
	{
		values[0] = BoolGetDatum(true);
		values[1] = BoolGetDatum(false);
		isnull[1] = false;
	}
	else
	{
		bool isvalid;
		const char *error = NULL;
		TransactionId xmin = InvalidTransactionId;
		TransactionId xmax = InvalidTransactionId;
		varatt_external toast_pointer;
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, val);

		values[0] = BoolGetDatum(true);
		values[1] = BoolGetDatum(true);
		isnull[1] = false;

		isvalid = toast_ptr_validate(&toast_pointer, &error, &xmin, &xmax, 0, NULL, NULL);

		values[2] = BoolGetDatum(isvalid);
		isnull[2] = false;

		if (isvalid)
		{
			isnull[4] = false;
			isnull[5] = false;
			values[4] = TransactionIdGetDatum(xmin);
			values[5] = TransactionIdGetDatum(xmax);
		}
		else
		{
			isnull[3] = false;
			values[3] = CStringGetTextDatum(error);
		}
	}

	rettup = heap_form_tuple(info->tupdesc, values, isnull);

	PG_RETURN_HEAPTUPLEHEADER(rettup->t_data);
}


static void
record_validation_error(Tuplestorestate *tstore,
						TupleDesc tupdesc,
						varatt_external *toast_pointer,
						HeapTuple htup,
						bool row_live,
						Name column_name,
						TransactionId toast_xmin,
						TransactionId toast_xmax,
						const char *error)
{
	Datum values[9];
	bool isnull[9];
	HeapTuple tup;

	/*
	 *	OUT row_ctid tid,
	 *	OUT row_live boolean,
	 *	OUT row_xmin xid,
	 *	OUT row_xmax xid,
	 *	OUT column_name name,
	 *	OUT toast_oid oid,
	 *	OUT toast_xmin xid,
	 *	OUT toast_xmax xid,
	 *	OUT error text
	 */

	isnull[0] = false;
	isnull[1] = false;
	isnull[2] = false;
	isnull[3] = false;
	isnull[4] = (column_name == NULL);
	isnull[5] = (toast_pointer == NULL);
	isnull[6] = !TransactionIdIsValid(toast_xmin);
	isnull[7] = !TransactionIdIsValid(toast_xmax);
	isnull[8] = false;

	values[0] = PointerGetDatum(&htup->t_self);
	values[1] = BoolGetDatum(row_live);
	values[2] = TransactionIdGetDatum(HeapTupleHeaderGetXmin(htup->t_data));
	values[3] = TransactionIdGetDatum(HeapTupleHeaderGetUpdateXid(htup->t_data));
	values[4] = (column_name != NULL) ? NameGetDatum(column_name) : (Datum)0;
	values[5] = (toast_pointer) ? ObjectIdGetDatum(toast_pointer->va_valueid) : (Datum)0;
	values[6] = TransactionIdGetDatum(toast_xmin);
	values[7] = TransactionIdGetDatum(toast_xmax);
	values[8] = CStringGetTextDatum(error);

	tup = heap_form_tuple(tupdesc, values, isnull);
	tuplestore_puttuple(tstore, tup);
}


static const char *
htsv_name(HTSV_Result s)
{
	switch (s)
	{
		case HEAPTUPLE_DEAD:				/* tuple is dead and deletable */
			return "DEAD";
		case HEAPTUPLE_LIVE:				/* tuple is live (committed, no deleter) */
			return "LIVE";
		case HEAPTUPLE_RECENTLY_DEAD:		/* tuple is dead, but not deletable yet */
			return "RECENTLY_DEAD";
		case HEAPTUPLE_INSERT_IN_PROGRESS:	/* inserting xact is still in progress */
			return "INSERT_IN_PROGRESS";
		case HEAPTUPLE_DELETE_IN_PROGRESS:	/* deleting xact is still in progress */
			return "DELETE_IN_PROGRESS";
	}
}

static bool
htsv_islive(HTSV_Result s)
{
	switch (s)
	{
		case HEAPTUPLE_DEAD:				/* tuple is dead and deletable */
			return false;
		case HEAPTUPLE_LIVE:				/* tuple is live (committed, no deleter) */
			return true;
		case HEAPTUPLE_RECENTLY_DEAD:		/* tuple is dead, but not deletable yet */
			return false;
		case HEAPTUPLE_INSERT_IN_PROGRESS:	/* inserting xact is still in progress */
			return true;
		case HEAPTUPLE_DELETE_IN_PROGRESS:	/* deleting xact is still in progress */
			return true;
	}
}

/*
 * toast_validate_table(tableoid)
 *
 *	OUT row_ctid tid,
 *	OUT row_live boolean,
 *	OUT row_xmin xid,
 *	OUT row_xmax xid,
 *	OUT column_name name,
 *	OUT toast_oid oid,
 *	OUT toast_xmin xid,
 *	OUT toast_xmax xid,
 *	OUT error text
 */
Datum
toast_validate_table(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	MemoryContext tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
													 "toast_validate_table per-row context",
													 ALLOCSET_SMALL_SIZES);
	Tuplestorestate *tupstore;
	TupleDesc	tupdesc;
	TupleDesc	result_tupdesc;
	Oid tableoid = PG_GETARG_OID(0);
	bool verbose = PG_GETARG_BOOL(1);
	Relation rel;
	TransactionId oldestXmin[2];
	HeapScanDesc heapScan;
	MemoryContext oldcontext;
	int natts;
	Datum *values;
	bool *isnull;

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	if (get_call_result_type(fcinfo, NULL, &result_tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "result type mismatch");

	if (result_tupdesc->natts != 9)
		elog(ERROR, "result type mismatch");

	/*
	 * open the rel and check access.
	 */
	rel = relation_open(tableoid, ExclusiveLock);

	/*
	 * Check permissions - mostly copied from VACUUM.
	 */
	if (!(pg_class_ownercheck(RelationGetRelid(rel), GetUserId()) ||
		  (pg_database_ownercheck(MyDatabaseId, GetUserId()) && !rel->rd_rel->relisshared)))
		ereport(ERROR,
				(errmsg("permission denied for relation \"%s\"",
						RelationGetRelationName(rel))));

	/*
	 * Check that it's of a vacuumable relkind.
	 *
	 * Toast tables are normally vacuumable but make no sense in this
	 * function. For partitioned tables, do the partitions separately.
	 */
	if (rel->rd_rel->relkind != RELKIND_RELATION &&
		rel->rd_rel->relkind != RELKIND_MATVIEW)
		ereport(ERROR,
				(errmsg("relation \"%s\" is not a vacuumable table",
						RelationGetRelationName(rel))));

	if (RELATION_IS_OTHER_TEMP(rel))
		ereport(ERROR,
				(errmsg("cannot access temp tables of other backends")));

	tupdesc = RelationGetDescr(rel);

	oldcontext = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);
	/*
	 * Copy the tupdesc into long-lived context because we're going to
	 * return it to the caller, who is responsible for freeing it.
	 */
	result_tupdesc = CreateTupleDescCopy(result_tupdesc);
	tupstore = tuplestore_begin_heap(rsinfo->allowedModes & SFRM_Materialize_Random,
									 false, work_mem);
	MemoryContextSwitchTo(oldcontext);

	/* let the caller know we're sending back a tuplestore */
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = result_tupdesc;

	/*
	 * Lock the toast table too - and if there isn't one, we're done
	 */
	if (OidIsValid(rel->rd_rel->reltoastrelid))
		LockRelationOid(rel->rd_rel->reltoastrelid, AccessExclusiveLock);
	else
	{
		relation_close(rel, NoLock);
		return (Datum) 0;
	}

	oldestXmin[0] = TransactionIdLimitedForOldSnapshots(GetOldestXmin(rel, PROCARRAY_FLAGS_VACUUM), rel);
	oldestXmin[1] = TransactionIdLimitedForOldSnapshots(RecentGlobalDataXmin, rel);
	if (!TransactionIdIsValid(oldestXmin[1]))
		oldestXmin[1] = oldestXmin[0];

	natts = tupdesc->natts;
	values = (Datum *) palloc(natts * sizeof(Datum));
	isnull = (bool *) palloc(natts * sizeof(bool));

	heapScan = heap_beginscan(rel, SnapshotAny, 0, (ScanKey) NULL);

	oldcontext = MemoryContextSwitchTo(tmpcontext);

	for (;;)
	{
		HeapTuple	tuple;
		Buffer		buf;
		HTSV_Result main_status[2];
		int i;

		MemoryContextReset(tmpcontext);

		CHECK_FOR_INTERRUPTS();

		tuple = heap_getnext(heapScan, ForwardScanDirection);
		if (tuple == NULL)
			break;

		buf = heapScan->rs_cbuf;

		LockBuffer(buf, BUFFER_LOCK_SHARE);

		main_status[0] = HeapTupleSatisfiesVacuum(tuple, oldestXmin[0], buf);
		main_status[1] = HeapTupleSatisfiesVacuum(tuple, oldestXmin[1], buf);

		LockBuffer(buf, BUFFER_LOCK_UNLOCK);

		if (main_status[0] != main_status[1] &&
			(verbose ||
			 !( (main_status[0] != HEAPTUPLE_RECENTLY_DEAD && main_status[1] == HEAPTUPLE_DEAD) ||
				(main_status[0] != HEAPTUPLE_DEAD && main_status[1] == HEAPTUPLE_RECENTLY_DEAD))))
		{
			record_validation_error(tupstore, result_tupdesc, NULL,
									tuple, true, NULL, InvalidTransactionId, InvalidTransactionId,
									psprintf("visibility mismatch: %s to OldestXmin, %s to RecentGlobalDataXmin",
											 htsv_name(main_status[0]), htsv_name(main_status[1])));
		}

		if (main_status[0] == HEAPTUPLE_DEAD && main_status[1] == HEAPTUPLE_DEAD)
			continue;

		heap_deform_tuple(tuple, tupdesc, values, isnull);

		for (i = 0; i < natts; ++i)
		{
			Form_pg_attribute att = TupleDescAttr(tupdesc, i);
			varatt_external toast_pointer;
			HTSV_Result toast_status[2];
			bool valid;
			TransactionId toast_xmin = InvalidTransactionId;
			TransactionId toast_xmax = InvalidTransactionId;
			const char *err = NULL;

			if (att->attisdropped || att->attlen != -1 || isnull[i])
				continue;
			if (!VARATT_IS_EXTERNAL_ONDISK(values[i]))
				continue;

			VARATT_EXTERNAL_GET_POINTER(toast_pointer, values[i]);

			valid = toast_ptr_validate(&toast_pointer, &err,
									   &toast_xmin, &toast_xmax,
									   2, oldestXmin, toast_status);
			if (!valid)
			{
				record_validation_error(tupstore, result_tupdesc, &toast_pointer,
										tuple, htsv_islive(main_status[0]), &(att->attname), InvalidTransactionId, InvalidTransactionId,
										err);
			}
			else
			{
				if (verbose && !htsv_islive(toast_status[0]))
				{
					record_validation_error(tupstore, result_tupdesc, &toast_pointer,
											tuple, htsv_islive(main_status[0]), &(att->attname), toast_xmin, toast_xmax,
											psprintf("%s heap row points to %s toast row (vs. OldestXmin)",
													 htsv_name(main_status[0]), htsv_name(toast_status[0])));
				}
				if (verbose && oldestXmin[0] != oldestXmin[1] && !htsv_islive(toast_status[1]))
				{
					record_validation_error(tupstore, result_tupdesc, &toast_pointer,
											tuple, htsv_islive(main_status[1]), &(att->attname), toast_xmin, toast_xmax,
											psprintf("%s heap row points to %s toast row (vs. RecentGlobalDataXmin)",
													 htsv_name(main_status[1]), htsv_name(toast_status[1])));
				}
			}
		}
	}

	heap_endscan(heapScan);

	relation_close(rel, NoLock);

	return (Datum) 0;
}

/* ------------------------------------------------------------------------ */
/* Stuff below here stolen from tuptoaster.c because static
 */

/* ----------
 * toast_open_indexes
 *
 *	Get an array of the indexes associated to the given toast relation
 *	and return as well the position of the valid index used by the toast
 *	relation in this array. It is the responsibility of the caller of this
 *	function to close the indexes as well as free them.
 */
static int
toast_open_indexes(Relation toastrel,
				   LOCKMODE lock,
				   Relation **toastidxs,
				   int *num_indexes)
{
	int			i = 0;
	int			res = 0;
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;

	/* Get index list of the toast relation */
	indexlist = RelationGetIndexList(toastrel);
	Assert(indexlist != NIL);

	*num_indexes = list_length(indexlist);

	/* Open all the index relations */
	*toastidxs = (Relation *) palloc(*num_indexes * sizeof(Relation));
	foreach(lc, indexlist)
		(*toastidxs)[i++] = index_open(lfirst_oid(lc), lock);

	/* Fetch the first valid index in list */
	for (i = 0; i < *num_indexes; i++)
	{
		Relation	toastidx = (*toastidxs)[i];

		if (toastidx->rd_index->indisvalid)
		{
			res = i;
			found = true;
			break;
		}
	}

	/*
	 * Free index list, not necessary anymore as relations are opened and a
	 * valid index has been found.
	 */
	list_free(indexlist);

	/*
	 * The toast relation should have one valid index, so something is going
	 * wrong if there is nothing.
	 */
	if (!found)
		elog(ERROR, "no valid index found for toast relation with Oid %u",
			 RelationGetRelid(toastrel));

	return res;
}

/* ----------
 * toast_close_indexes
 *
 *	Close an array of indexes for a toast relation and free it. This should
 *	be called for a set of indexes opened previously with toast_open_indexes.
 */
static void
toast_close_indexes(Relation *toastidxs, int num_indexes, LOCKMODE lock)
{
	int			i;

	/* Close relations and clean up things */
	for (i = 0; i < num_indexes; i++)
		index_close(toastidxs[i], lock);
	pfree(toastidxs);
}

/* ----------
 * init_toast_snapshot
 *
 *	Initialize an appropriate TOAST snapshot.  We must use an MVCC snapshot
 *	to initialize the TOAST snapshot; since we don't know which one to use,
 *	just use the oldest one.  This is safe: at worst, we will get a "snapshot
 *	too old" error that might have been avoided otherwise.
 */
static void
init_toast_snapshot(Snapshot toast_snapshot)
{
	Snapshot	snapshot = GetOldestSnapshot();

	if (snapshot == NULL)
		elog(ERROR, "no known snapshots");

	InitToastSnapshot(*toast_snapshot, snapshot->lsn, snapshot->whenTaken);
}
