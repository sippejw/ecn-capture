CREATE TABLE public.ecn_measurements
(
    start_time bigint,
    last_updated bigint,
    server_port smallint,
    client_ece smallint,
    client_cwr smallint,
    server_ece smallint,
    client_fin smallint,
    client_rst smallint,
    server_fin smallint,
    server_rst smallint,
    stale smallint,
    client_00 integer,
    client_01 integer,
    client_10 integer,
    client_11 integer,
    server_00 integer,
    server_01 integer,
    server_10 integer,
    server_11 integer,
    client_cc character varying COLLATE pg_catalog."default",
    server_cc character varying COLLATE pg_catalog."default"
)
