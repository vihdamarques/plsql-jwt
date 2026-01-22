# plsql-jwt

PL/SQL package to handle JWT spec

## Requirements

Oracle Database 19c+

## Current Features

- Encode JWT Token signed with the following algorithms:
  - HMAC-SHA256
  - HMAC-SHA384
  - HMAC-SHA512
  - RSA-SHA256
  - RSA-SHA384
  - RSA-SHA512
- Decode JWT Token
- Verify JWT Token against a key (Asymmetric or Plain Text) and Expiration Time (if p_timestamp is provided)

## Examples

### Encode

#### Signed with HMAC-SHA256 (Plain Text Key)

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
  l_payload.iat := sysdate;
  l_payload.exp := l_payload.iat + interval '1' hour; -- 1 hour expiration
  l_payload.claims('custom_role') := 'admin';
  --
  l_jwt := pkg_jwt.encode (
             p_header  => l_header,
             p_payload => l_payload,
             p_key     => l_key
           );

  dbms_output.put_line('JWT: ' || l_jwt);
end;
/
````

#### Signed with RSA-SHA256 (Asymmetric Private Key)

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
  l_payload.iat := sysdate;
  l_payload.exp := l_payload.iat + interval '1' hour; -- 1 hour expiration
  l_payload.claims('custom_role') := 'admin';
  --
  l_jwt := pkg_jwt.encode (
             p_header  => l_header,
             p_payload => l_payload,
             p_key     => l_key
           );

  dbms_output.put_line('JWT: ' || l_jwt);
end;
/
````

### Decode

````sql
set serveroutput on size unlimited
declare
  l_jwt        pkg_jwt.r_jwt;
  l_claim_name pkg_jwt.s_claim_name;
begin
  l_jwt := pkg_jwt.decode(p_jwt      => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteV9pc3N1ZXIiLCJzdWIiOiJteV9zdWJqZWN0IiwiYXVkIjoibXlfYXVkaWVuY2UiLCJleHAiOjE3NjkxMTAzMTcsIm5iZiI6bnVsbCwiaWF0IjoxNzY5MTA2NzE3LCJqdGkiOm51bGwsImN1c3RvbV9yb2xlIjoiYWRtaW4ifQ.63X6XXVrlGqA0kKu4s2Ct-302_PQsDC22-xGORkmYFM');
  dbms_output.put_line('--- Header ---');
  dbms_output.put_line('alg: ' || l_jwt.header.alg);
  dbms_output.put_line('typ: ' || l_jwt.header.typ);
  dbms_output.put_line('--- Payload ---');
  dbms_output.put_line('iss: ' || l_jwt.payload.iss);
  dbms_output.put_line('sub: ' || l_jwt.payload.sub);
  dbms_output.put_line('aud: ' || l_jwt.payload.aud);
  dbms_output.put_line('exp: ' || l_jwt.payload.exp);
  dbms_output.put_line('nbf: ' || l_jwt.payload.nbf);
  dbms_output.put_line('iat: ' || l_jwt.payload.iat);
  dbms_output.put_line('jti: ' || l_jwt.payload.jti);

  l_claim_name := l_jwt.payload.claims.first;
  loop
    exit when l_claim_name is null;
    dbms_output.put_line(l_claim_name || ': ' || l_jwt.payload.claims(l_claim_name));
    l_claim_name := l_jwt.payload.claims.next(l_claim_name);
  end loop;

  dbms_output.put_line('--- Signature ---');
  dbms_output.put_line('sig: ' || l_jwt.signature_base64);
end;
/
````

### Verify

````sql
set serveroutput on size unlimited
declare
  l_valid boolean;
begin
  l_valid := pkg_jwt.verify(p_jwt  => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteV9pc3N1ZXIiLCJzdWIiOiJteV9zdWJqZWN0IiwiYXVkIjoibXlfYXVkaWVuY2UiLCJleHAiOjE3NjkxMTAzMTcsIm5iZiI6bnVsbCwiaWF0IjoxNzY5MTA2NzE3LCJqdGkiOm51bGwsImN1c3RvbV9yb2xlIjoiYWRtaW4ifQ.63X6XXVrlGqA0kKu4s2Ct-302_PQsDC22-xGORkmYFM',
                            p_key  => 'my_secret_key',
                            p_date => sysdate);
  dbms_output.put_line('JWT is ' || case when l_valid then 'Valid' else 'Invalid' end);
end;
/
````
