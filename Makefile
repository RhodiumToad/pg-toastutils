
MODULE_big = pg_toastutils

EXTENSION = pg_toastutils
DATA = pg_toastutils--1.0.sql

OBJS = toastutils.o

PG_CONFIG = pg_config
PGXS = $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
