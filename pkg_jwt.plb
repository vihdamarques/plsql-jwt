create or replace package body pkg_jwt as
  function is_valid_alg(p_alg in varchar2) return boolean is
  begin
    return p_alg in (C_ALG_HS256, C_ALG_HS384, C_ALG_HS512, C_ALG_RS256, C_ALG_RS384, C_ALG_RS512, C_ALG_NONE);
  end is_valid_alg;

  function is_valid_typ(p_typ in varchar2) return boolean is
  begin
    return p_typ = C_TYP_JWT;
  end is_valid_typ;

  function get_epoch(p_timestamp in timestamp, p_timezone varchar2 default 'UTC') return number is
  begin
    return trunc((cast(p_timestamp at time zone p_timezone as date) - to_date('01/01/1970', 'dd/mm/yyyy')) * 24 * 60 * 60);
  end get_epoch;

  function base64url_encode(p_string in varchar2) return varchar2 is
  begin
    return translate(utl_i18n.raw_to_char(utl_encode.base64_encode(utl_i18n.string_to_raw(p_string, G_CHARSET)), G_CHARSET), '+/=' || chr(10) || chr(13), '-_');
  end base64url_encode;

  function base64url_encode(p_raw in raw) return varchar2 is
  begin
    return translate(utl_i18n.raw_to_char(utl_encode.base64_encode(p_raw), G_CHARSET), '+/=' || chr(10) || chr(13), '-_');
  end base64url_encode;

  function get_token(p_header  in r_header  default cast(null as r_header),
                     p_payload in r_payload default cast(null as r_payload),
                     p_key     in varchar2) return varchar2 is
    l_header_json      json_object_t := json_object_t();
    l_header_base64    varchar2(4000);
    l_payload_json     json_object_t := json_object_t();
    l_payload_base64   varchar2(4000);
    l_signature        raw(4000);
    l_signature_base64 varchar2(4000);
    l_jwt              varchar2(4000);
    l_claim_name       s_claim_name;
    l_key             varchar2(4000) := p_key;
  begin
    if not is_valid_alg(p_header.alg) then
      raise_application_error(-20001, 'Invalid algorithm specified in header.');
    end if;

    if not is_valid_typ(p_header.typ) then
      raise_application_error(-20002, 'Invalid type specified in header.');
    end if;

    l_header_json.put('alg', p_header.alg);
    l_header_json.put('typ', p_header.typ);
    l_header_base64 := base64url_encode(p_string => l_header_json.to_string());

    l_payload_json.put('iss', p_payload.iss);
    l_payload_json.put('sub', p_payload.sub);
    l_payload_json.put('aud', p_payload.aud);
    l_payload_json.put('exp', p_payload.exp);
    l_payload_json.put('nbf', p_payload.nbf);
    l_payload_json.put('iat', p_payload.iat);
    l_payload_json.put('jti', p_payload.jti);

    l_claim_name := p_payload.claims.first;
    loop
      exit when l_claim_name is null;
      l_payload_json.put(l_claim_name, p_payload.claims(l_claim_name));
      l_claim_name := p_payload.claims.next(l_claim_name);
    end loop;
    l_payload_base64 := base64url_encode(p_string => l_payload_json.to_string());

    l_jwt := l_header_base64 || '.' || l_payload_base64;

    if p_header.alg like 'HS%' then
      l_signature := sys.dbms_crypto.mac (
                       src => utl_i18n.string_to_raw(l_jwt, G_CHARSET),
                       typ => case p_header.alg
                                when C_ALG_HS256 then sys.dbms_crypto.hmac_sh256
                                when C_ALG_HS384 then sys.dbms_crypto.hmac_sh384
                                when C_ALG_HS512 then sys.dbms_crypto.hmac_sh512
                              end,
                       key => utl_i18n.string_to_raw(p_key, G_CHARSET)
                     );
    elsif p_header.alg like 'RS%' then
      l_key := replace(replace(replace(replace(p_key, '-----BEGIN PRIVATE KEY-----', ''), '-----END PRIVATE KEY-----', ''), chr(10), ''), chr(13), '');
      l_signature := sys.dbms_crypto.sign (
                       src        => utl_i18n.string_to_raw(l_jwt, G_CHARSET),
                       prv_key    => utl_raw.cast_to_raw(l_key),
                       pubkey_alg => sys.dbms_crypto.key_type_rsa,
                       sign_alg   => case p_header.alg
                                       when C_ALG_RS256 then sys.dbms_crypto.sign_sha256_rsa
                                       when C_ALG_RS384 then sys.dbms_crypto.sign_sha384_rsa
                                       when C_ALG_RS512 then sys.dbms_crypto.sign_sha512_rsa
                                     end
                     );
    else
      l_signature := null;
    end if;
    l_signature_base64 := case when l_signature is not null then base64url_encode(p_raw => l_signature) end;

    l_jwt := l_jwt || '.' || l_signature_base64;

    return l_jwt;
  end get_token;
end pkg_jwt;
/
