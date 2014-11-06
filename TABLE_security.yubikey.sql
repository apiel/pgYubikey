CREATE TABLE security.yubikey_ybk
(
  id_ybk integer NOT NULL,
  public_ybk character varying(12),
  internal_ybk character varying(12),
  aes_ybk character varying(32),
  counter_ybk integer,
  time_ybk integer,
  CONSTRAINT yubikey_ybk_pkey PRIMARY KEY (id_ybk)
);
