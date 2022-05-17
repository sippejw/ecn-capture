CREATE TABLE public.udp_ecn_measurements
(
    start_time bigint,
    last_updated bigint,
    server_port smallint,
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
    is_ipv4 smallint,
)
