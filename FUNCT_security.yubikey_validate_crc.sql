CREATE OR REPLACE FUNCTION security.yubikey_validate_crc(v_data varchar) RETURNS int
    AS $BODY$
DECLARE
   v_res int;
   v_crc bigint;
   v_b bigint;
   v_n bigint;
BEGIN
	v_res = -1; -- CRC invalid
	v_crc = 65535;
	FOR i IN 0..15 LOOP
		EXECUTE 'SELECT x''' || substr(v_data, i*2+1, 2) || '''::int' INTO v_b;
		v_crc = (v_crc # (v_b & 255));
		FOR j IN 1..8 LOOP
			v_n = v_crc & 1;
			v_crc = v_crc >> 1;
			IF v_n != 0
			THEN
				v_crc = v_crc # 33800;
			END IF;
		END LOOP;
	END LOOP;
	IF v_crc = 61624
	THEN
		v_res = 1;
	END IF;
	RETURN v_res;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE;
