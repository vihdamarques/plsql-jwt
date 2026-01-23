create or replace package body pkg_jwt as
  function is_valid_alg(p_alg in varchar2) return boolean is
  begin
    return p_alg in (C_ALG_HS256, C_ALG_HS384, C_ALG_HS512, C_ALG_RS256, C_ALG_RS384, C_ALG_RS512, C_ALG_NONE);
  end is_valid_alg;

  function is_valid_typ(p_typ in varchar2) return boolean is
  begin
    return p_typ = C_TYP_JWT;
  end is_valid_typ;

  function date2epoch(p_date in date) return number is
  begin
    return trunc((cast(p_date at time zone 'UTC' as date) - to_date('01/01/1970', 'dd/mm/yyyy')) * 24 * 60 * 60);
  end date2epoch;

  function epoch2date(p_epoch in number) return date is
  begin
    return cast(from_tz(cast(to_date('01/01/1970', 'dd/mm/yyyy') + (p_epoch / 24 / 60 / 60) as timestamp), 'UTC') at time zone sessiontimezone as date);
  end epoch2date;

  function base64url_encode(p_string in varchar2) return varchar2 is
  begin
    return translate(utl_i18n.raw_to_char(utl_encode.base64_encode(utl_i18n.string_to_raw(p_string, G_CHARSET)), G_CHARSET), '+/=' || chr(10) || chr(13), '-_');
  end base64url_encode;

  function base64url_encode(p_raw in raw) return varchar2 is
  begin
    return translate(utl_i18n.raw_to_char(utl_encode.base64_encode(p_raw), G_CHARSET), '+/=' || chr(10) || chr(13), '-_');
  end base64url_encode;

  function base64url_decode(p_string in varchar2) return varchar2 is
  begin
    return utl_i18n.raw_to_char(utl_encode.base64_decode(utl_i18n.string_to_raw(translate(p_string, '-_', '+/'), G_CHARSET)), G_CHARSET);
  end base64url_decode;

  function sign(p_data in varchar2, p_key in varchar2, p_alg in varchar2) return varchar2 is
    l_signature raw(32767);
    l_key       varchar2(32767) := p_key;
  begin
    if p_alg like 'HS%' then
      l_signature := sys.dbms_crypto.mac (
                       src => utl_i18n.string_to_raw(p_data, G_CHARSET),
                       typ => case p_alg
                                when C_ALG_HS256 then sys.dbms_crypto.hmac_sh256
                                when C_ALG_HS384 then sys.dbms_crypto.hmac_sh384
                                when C_ALG_HS512 then sys.dbms_crypto.hmac_sh512
                              end,
                       key => utl_i18n.string_to_raw(l_key, G_CHARSET)
                     );
    elsif p_alg like 'RS%' then
      l_key := replace(replace(replace(replace(p_key, '-----BEGIN PRIVATE KEY-----', ''), '-----END PRIVATE KEY-----', ''), chr(10), ''), chr(13), '');
      l_signature := sys.dbms_crypto.sign (
                       src        => utl_i18n.string_to_raw(p_data, G_CHARSET),
                       prv_key    => utl_raw.cast_to_raw(l_key),
                       pubkey_alg => sys.dbms_crypto.key_type_rsa,
                       sign_alg   => case p_alg
                                       when C_ALG_RS256 then sys.dbms_crypto.sign_sha256_rsa
                                       when C_ALG_RS384 then sys.dbms_crypto.sign_sha384_rsa
                                       when C_ALG_RS512 then sys.dbms_crypto.sign_sha512_rsa
                                     end
                     );
    else
      l_signature := null;
    end if;

    return case when l_signature is not null then base64url_encode(p_raw => l_signature) end;
  end sign;

  function encode(p_header  in r_header  default cast(null as r_header),
                  p_payload in r_payload default cast(null as r_payload),
                  p_key     in varchar2) return varchar2 is
    l_header_json  json_object_t := json_object_t();
    l_payload_json json_object_t := json_object_t();
    l_claim_name   s_claim_name;
    --
    l_header_base64    varchar2(32767);
    l_payload_base64   varchar2(32767);
    l_signature_base64 varchar2(32767);
    l_jwt              varchar2(32767);
  begin
    if not is_valid_alg(p_header.alg) then
      raise_application_error(-20001, 'Invalid algorithm specified in header.');
    end if;

    if not is_valid_typ(p_header.typ) then
      raise_application_error(-20002, 'Invalid type specified in header.');
    end if;

    l_header_json.put('alg', p_header.alg);
    l_header_json.put('typ', p_header.typ);
    l_header_base64  := base64url_encode(p_string => l_header_json.to_string());

    l_payload_json.put('iss', p_payload.iss);
    l_payload_json.put('sub', p_payload.sub);
    l_payload_json.put('aud', p_payload.aud);
    l_payload_json.put('exp', date2epoch(p_payload.exp));
    l_payload_json.put('nbf', date2epoch(p_payload.nbf));
    l_payload_json.put('iat', date2epoch(p_payload.iat));
    l_payload_json.put('jti', p_payload.jti);

    l_claim_name := p_payload.claims.first;
    loop
      exit when l_claim_name is null;
      l_payload_json.put(l_claim_name, p_payload.claims(l_claim_name));
      l_claim_name := p_payload.claims.next(l_claim_name);
    end loop;
    l_payload_base64 := base64url_encode(p_string => l_payload_json.to_string());

    l_jwt := l_header_base64 || '.' || l_payload_base64;

    l_signature_base64 := sign(p_data => l_jwt, p_key => p_key, p_alg => p_header.alg);
    l_jwt := l_jwt || '.' || l_signature_base64;

    return l_jwt;
  end encode;

  function decode(p_jwt in varchar2) return r_jwt is
    l_jwt              r_jwt;
    l_header_json      json_object_t := json_object_t();
    l_payload_json     json_object_t := json_object_t();
    l_payload_claims   json_key_list;
    l_claim_name       s_claim_name;
  begin
    l_jwt.header_base64    := regexp_replace(p_jwt, '^([^\.]+)\.([^\.]+).([^\.]*)', '\1');
    l_jwt.payload_base64   := regexp_replace(p_jwt, '^([^\.]+)\.([^\.]+).([^\.]*)', '\2');
    l_jwt.signature_base64 := regexp_replace(p_jwt, '^([^\.]+)\.([^\.]+).([^\.]*)', '\3');

    l_header_json  := json_object_t.parse(base64url_decode(p_string => l_jwt.header_base64));
    l_payload_json := json_object_t.parse(base64url_decode(p_string => l_jwt.payload_base64));

    l_jwt.header.alg := l_header_json.get_string('alg');
    l_jwt.header.typ := l_header_json.get_string('typ');

    l_jwt.payload.iss := l_payload_json.get_string('iss');
    l_jwt.payload.sub := l_payload_json.get_string('sub');
    l_jwt.payload.aud := l_payload_json.get_string('aud');
    l_jwt.payload.exp := epoch2date(l_payload_json.get_number('exp'));
    l_jwt.payload.nbf := epoch2date(l_payload_json.get_number('nbf'));
    l_jwt.payload.iat := epoch2date(l_payload_json.get_number('iat'));
    l_jwt.payload.jti := l_payload_json.get_string('jti');

    l_payload_claims := l_payload_json.get_keys();

    for i in 1 .. l_payload_claims.count loop
      l_claim_name := l_payload_claims(i);
      if l_claim_name not in ('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti') then
        l_jwt.payload.claims(l_claim_name) := l_payload_json.get_string(l_claim_name);
      end if;
    end loop;

    return l_jwt;
  end decode;

  function verify(p_jwt  in varchar2,
                  p_key  in varchar2,
                  p_date in date default null) return boolean is
    l_jwt         r_jwt;
    l_signed_data varchar2(32767);
  begin
    l_jwt := decode(p_jwt => p_jwt);

    l_signed_data := l_jwt.header_base64 || '.' || l_jwt.payload_base64;

    return l_jwt.signature_base64 = sign(p_data => l_signed_data, p_key => p_key, p_alg => l_jwt.header.alg)
           and (p_date is null or l_jwt.payload.exp is null or l_jwt.payload.exp >= p_date)
           and (p_date is null or l_jwt.payload.nbf is null or l_jwt.payload.nbf <  p_date)
           ;
  end verify;
end pkg_jwt;
/
