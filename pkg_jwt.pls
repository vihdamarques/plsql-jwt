create or replace package pkg_jwt as
  -- Constants
  C_ALG_HS256 constant varchar2(10) := 'HS256';
  C_ALG_HS384 constant varchar2(10) := 'HS384';
  C_ALG_HS512 constant varchar2(10) := 'HS512';
  C_ALG_RS256 constant varchar2(10) := 'RS256';
  C_ALG_RS384 constant varchar2(10) := 'RS384';
  C_ALG_RS512 constant varchar2(10) := 'RS512';
  C_ALG_NONE  constant varchar2(10) := 'none';
  C_TYP_JWT   constant varchar2(10) := 'JWT';

  -- Globals
  G_CHARSET constant varchar2(20) := 'AL32UTF8';

  -- Types
  subtype s_claim_name  is varchar2(100);
  subtype s_claim_value is varchar2(1000);
  type t_claims is table of s_claim_value index by s_claim_name;
  type r_header is record (
    alg varchar2(10),
    typ varchar2(10) default C_TYP_JWT
  );
  type r_payload is record (
    -- Registered Claims
    iss varchar2(255), -- Issuer
    sub varchar2(255), -- Subject
    aud varchar2(255), -- Audience
    exp date, -- Expiration Time
    nbf date, -- Not Before
    iat date, -- Issued At
    jti varchar2(255), -- JWT ID
    -- Custom Claims
    claims t_claims -- Private / Public Claims
  );
  type r_jwt is record (
    header           r_header,
    payload          r_payload,
    header_base64    varchar2(32767),
    payload_base64   varchar2(32767),
    signature_base64 varchar2(32767)
  );

  function encode(p_header  in r_header  default cast(null as r_header),
                  p_payload in r_payload default cast(null as r_payload),
                  p_key     in varchar2) return varchar2;

  function decode(p_jwt in varchar2) return r_jwt;

  function verify(p_jwt  in varchar2,
                  p_key  in varchar2,
                  p_date in date default null) return boolean;
end pkg_jwt;
/
