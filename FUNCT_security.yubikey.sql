CREATE OR REPLACE FUNCTION security.yubikey(v_otp varchar) RETURNS int
    AS $BODY$
DECLARE
   v_res int;
   v_public varchar;
   v_aes varchar;
   v_encrypted_text varchar;
   v_plain_text varchar;
   v_internal varchar;
   v_counter int;
   -- v_time int;
BEGIN
	v_res = -1; -- public key invalid
	v_public = substr(v_otp, 1, 12);
	RAISE NOTICE 'Public key %', v_public;

	SELECT INTO v_aes ybk.aes_ybk FROM security.yubikey_ybk ybk WHERE ybk.public_ybk = v_public;

	IF v_aes IS NOT NULL
	THEN
		RAISE NOTICE 'AES %', v_aes;
		v_encrypted_text = substr(v_otp, 13);
		RAISE NOTICE 'Encrypted text (modhex) %', v_encrypted_text;
		v_encrypted_text = translate(v_encrypted_text, 'cbdefghijklnrtuv', '0123456789abcdef');
		RAISE NOTICE 'Encrypted text (hex) %', v_encrypted_text;
		SELECT INTO v_plain_text encode(decrypt(CAST('\x' || v_encrypted_text AS bytea), CAST('\x' || v_aes AS bytea), 'aes-ecb'), 'hex');
		RAISE NOTICE 'Plain text %', v_plain_text;
		v_internal = substr(v_plain_text, 1, 12);
		RAISE NOTICE 'Internal key %', v_internal;
		EXECUTE 'SELECT x''' || substr(v_plain_text, 15, 2) || substr(v_plain_text, 13, 2) || '''::int' INTO v_counter;
		RAISE NOTICE 'Internal counter %', v_counter;
		-- EXECUTE 'SELECT x''' || substr(v_plain_text, 21, 2) || substr(v_plain_text, 19, 2) || substr(v_plain_text, 17, 2) || '''::int' INTO v_time;
		-- RAISE NOTICE 'Internal time %', v_time;
		SELECT INTO v_res ybk.id_ybk FROM security.yubikey_ybk ybk WHERE ybk.public_ybk = v_public 
			AND ybk.internal_ybk = v_internal AND ybk.counter_ybk < v_counter; -- AND ybk.time_ybk < v_time; <--wrong because session time...
		IF v_res IS NULL
		THEN
			v_res = -2; -- otp invalid (here we could also try to find out if the keys was (-3)reused or (-4)timeout)
		ELSE
			-- UPDATE security.yubikey_ybk SET counter_ybk = v_counter, time_ybk = v_time WHERE id_ybk = v_res;
			UPDATE security.yubikey_ybk SET counter_ybk = v_counter WHERE id_ybk = v_res;
		END IF;
		RAISE NOTICE 'Result %', v_res;
	END IF;
	
	RETURN v_res;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE;
  
-- select security.yubikey('vvkkefrufhjhfdfvhldvnrbveuckujvgrubgttgutddt');
