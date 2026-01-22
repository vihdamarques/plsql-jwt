# plsql-jwt

PL/SQL package to handle JWT spec

## Requirements

Oracle Database 19c+

## Current Features

- Generate JWT Token signed with the following algorithms:
  - HMAC-SHA256
  - HMAC-SHA384
  - HMAC-SHA512
  - RSA-SHA256
  - RSA-SHA384
  - RSA-SHA512

## Examples

### Signing with HMAC-SHA256 (Plain Text Key)

````sql
set serveroutput on size unlimited
declare
  l_header  pkg_jwt.r_header;
  l_payload pkg_jwt.r_payload;
  l_key     varchar2(4000) := 'my_secret_key';
  l_jwt     varchar2(4000);
begin
  l_header.alg := pkg_jwt.C_ALG_HS256;
  --
  l_payload.iss := 'my_issuer';
  l_payload.sub := 'my_subject';
  l_payload.aud := 'my_audience';
  l_payload.iat := pkg_jwt.get_epoch(systimestamp);
  l_payload.exp := l_payload.iat + 3600; -- 1 hour expiration
  l_payload.claims('custom_role') := 'admin';
  --
  l_jwt := pkg_jwt.get_token (
             p_header  => l_header,
             p_payload => l_payload,
             p_key     => l_key
           );

  dbms_output.put_line('JWT: ' || l_jwt);
end;
/
````

### Signing with RSA-SHA256 (Assimetric Private Key)

````sql
set serveroutput on size unlimited
declare
  l_header  pkg_jwt.r_header;
  l_payload pkg_jwt.r_payload;
  l_key     varchar2(4000) := ''; -- Load a base64 private key here
  l_jwt     varchar2(4000);
begin
  l_header.alg := pkg_jwt.C_ALG_RS256;
  --
  l_payload.iss := 'my_issuer';
  l_payload.sub := 'my_subject';
  l_payload.aud := 'my_audience';
  l_payload.iat := pkg_jwt.get_epoch(systimestamp);
  l_payload.exp := l_payload.iat + 3600; -- 1 hour expiration
  l_payload.claims('custom_role') := 'admin';
  --
  l_jwt := pkg_jwt.get_token (
             p_header  => l_header,
             p_payload => l_payload,
             p_key     => l_key
           );

  dbms_output.put_line('JWT: ' || l_jwt);
end;
/
````
