# credentials

크리덴셜을 **운영자도 볼 수 없게** 보관하고, 쓸 때마다 **지울 수 없는 기록을 먼저 남긴 뒤** 쓰는 금고의 핵심 엔진.

## 구조

| 크레이트 | 역할 |
| --- | --- |
| `engine` | 비밀값 타입, 정책, 템플릿, 레코드 암호화, 선기록 로그, 응답 처리, 노드 |
| `verify` | 노드 로그를 독립적으로 검증하는 CLI: `verify <log.jsonl> <node-public-key>` |

크리덴셜 종류와 프로토콜 흐름이 코드에 없다. 레코드는 **이름 붙은 필드 묶음**(바이트: 텍스트·이미지·키 파일 무엇이든)이다. 값을 어디에 어떻게 쓰는지는 기기가 서명한 정책 안에 **operation**으로 적는다. 새 서비스를 붙일 때 코드를 고치지 않는다.

## 정책

```json
{
  "fields": [
    {"name": "client_id", "secret": false},
    {"name": "client_secret", "secret": true},
    {"name": "refresh_token", "secret": true},
    {"name": "access_token", "secret": true, "optional": true}
  ],
  "operations": [
    {"kind": "http", "name": "refresh",
     "destinations": [{"host": "auth.example.com", "port": 443}], "methods": [],
     "steps": [{
       "request": {"from": "fixed", "method": "POST", "path": "/oauth/token"},
       "inject": [{"target": {"kind": "body"},
                   "template": "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}&client_id={{pct(client_id)}}&client_secret={{pct(client_secret)}}"}],
       "capture": [{"source": {"from": "json", "pointer": "/access_token"},
                    "into": {"kind": "field", "name": "access_token"}}]
     }]},
    {"kind": "http", "name": "call",
     "destinations": [{"host": "api.example.com", "port": 443}], "methods": ["GET", "POST"],
     "steps": [{"inject": [{"target": {"kind": "header", "name": "Authorization"},
                            "template": "Bearer {{access_token}}"}]}]}
  ]
}
```

operation은 세 종류다.

| 종류 | 하는 일 |
| --- | --- |
| `http` | 1~8개의 **step**. step마다 호출자 요청(`caller`)이나 정책이 고정한 요청(`fixed`)을 보내고, 값을 주입하고, 응답에서 값을 **캡처**한다. 마지막 step의 응답만 호출자에게 간다 |
| `stream` | TLS 연결 하나에서 `send`/`expect` 스크립트를 실행한 뒤, 인증된 연결로 호출자의 송수신을 중계한다 (IMAP·SMTP·줄 단위 프로토콜) |
| `derive` | 템플릿 출력을 호출자에게 돌려준다. 비밀이 **되돌릴 수 있는 형태로 섞여 있으면 서명 단계에서 거부**된다(taint 검사) |

- **주입 대상**: `header` · `query` · `path_param` · `body` 넷뿐이고 나머지는 전부 템플릿이다.
- **캡처 소스**: `status` · `header` · `header_param`(`WWW-Authenticate`의 `nonce=` 같은 값) · `cookie`(`Set-Cookie`) · `json`(JSON pointer) · `between` · `all`. stream에서는 `between`·`all`만 쓴다.
- **캡처 저장처**:
  - `field`: 레코드 필드를 갱신한다. 노드가 로그에 `update`를 남긴 뒤 **새 레코드로 다시 봉인해 돌려준다**. 뒤 step이 실패해도 새 레코드는 돌려준다.
  - `temp`: 같은 operation의 뒤 step만 읽는 값이다(세션 쿠키, challenge nonce). `secret` 표시가 있으면 taint·redaction·reflection 대상이 된다.
- **mTLS**: `http`·`stream`에 `"identity": {"cert": "{{cert}}", "key": "{{key}}"}`를 두면 클라이언트 인증서가 `Transport`에만 전달된다.
- **응답 처리**: 캡처한 비밀은 응답에서 `[redacted]`로 바뀐다(원문·JSON 이스케이프). 그 뒤 남은 비밀 흔적이 있으면 응답을 통째로 버린다.

## 템플릿

`{{ }}` 안에는 이름(필드나 temp), 변수, 문자열 리터럴, 함수 호출, `+` 연결만 쓸 수 있다. 분기와 반복은 없다.

- **변수**: `$method` `$host` `$path` `$pathname` `$query` `$body` `$unix` `$unix_ms` `$boundary` `$nonce` `$input`(derive 전용). stream과 identity에서는 `$host` `$unix` `$unix_ms` `$nonce`만 쓴다.
- **기본 함수**(코드에 있는 건 이것뿐):

| 분류 | 함수 |
| --- | --- |
| 인코딩 | `b64` `b64raw` `b64url` `b64urlraw` `b64decode` `b32decode` `hex` `hexdecode` `pct` `pctdecode` `json` `pem` |
| 문자열 | `upper` `lower` `trim` `replace` `json_set` `canonical_query` `time` `len` `be16` `be32` `xor` |
| 해시·MAC | `md5` `sha1` `sha256` `sha512` `keccak256` `hmac_sha1` `hmac_sha256` `hmac_sha512` `pbkdf2_sha256` `totp` |
| 서명 | `ed25519_sign` `p256_sign` `p256_sign_der` `p384_sign` `k256_sign` `k256_sign_recoverable` `rsa_sign_pkcs1_sha256` `rsa_sign_pss_sha256` |
| 암호화 | `aes_gcm_encrypt` `aes_cbc_encrypt` |

- **taint 규칙**: 인코딩·문자열 함수는 taint를 유지한다. 해시·MAC·서명·`len`은 taint를 없앤다. 암호화는 **키가 비밀일 때만** taint를 없앤다. 누구나 아는 키로 비밀을 암호화하면 되돌릴 수 있기 때문이다.

| 방식 | 정책 |
| --- | --- |
| Bearer · 쿠키 · API 키 | header 템플릿 하나 |
| 텔레그램 봇 경로 | path_param `{{token}}`, 경로 `/bot{token}/getMe` |
| 거래소 HMAC 서명 | query `signature` = `{{ hex(hmac_sha256(secret, $query)) }}` |
| AWS SigV4 | header 두 개 (`time`, `canonical_query`, 중첩 `hmac_sha256`). 테스트가 공식 벡터 재현 |
| HTTP Digest | step 1에서 `header_param`으로 `realm`·`nonce` 캡처, step 2에서 `md5`로 응답 계산. RFC 2617 벡터 재현 |
| OAuth 토큰 갱신 | `fixed` POST, `json` 캡처를 `field`에 저장 → 새 레코드 |
| 세션 로그인 | `fixed` POST /login, `cookie` 캡처를 `temp`에 저장 → 호출자 요청에 `Cookie` |
| JWT RS256 | derive = `b64urlraw(header) + "." + b64urlraw($input) + "." + b64urlraw(rsa_sign_pkcs1_sha256(pem(key), ...))` |
| 이더리움 서명 | derive = `{{ k256_sign_recoverable(key, keccak256($input)) }}` |
| IMAP 로그인 | stream: expect 인사말 → send `a1 LOGIN {{user}} {{password}}` → expect → 호출자 명령 중계 |
| OTP | derive = `{{ totp(b32decode(seed)) }}` |
| mTLS | `identity` |
| 이미지·서명 그림 업로드 | body = `{{image}}` 또는 multipart 템플릿 + `{{$boundary}}` |

## 한 번의 사용 순서

1. 소유자 grant가 유효한지 확인 (최대 30일)
2. 정책 서명을 grant의 기기 키로 검증하고, 요청이 operation 안인지 확인
3. 레코드 복호화(AAD가 id·소유자·서명된 정책을 묶어, 바꿔치기하면 열리지 않음), 템플릿 렌더링
4. 로그 엔트리를 sink가 확인해야 `Confirmed`가 생긴다. 이게 없으면 전송·연결 함수를 호출할 수 없다(타입으로 강제). HTTP는 요청마다, stream은 연결마다 엔트리 하나
5. `Transport`로 전송. 값이 엔진 밖으로 나가는 유일한 경로
6. 캡처한 값으로 필드가 바뀌면 `update` 엔트리를 남긴 뒤 재봉인
7. 캡처한 비밀을 redaction한 뒤에도 응답에 비밀이 되돌아오면(원문·base64·퍼센트·JSON 이스케이프·hex, 렌더링된 값) 버림

## 보장하는 것

- `Secret`은 출력·복제·직렬화가 안 되고, drop 시 0으로 덮어씀. 외부 크레이트는 값을 읽을 수 없음 (`compile_fail` 문서 테스트)
- 정책은 기기 서명 + 암호문 AAD로 이중으로 묶임. 운영자가 목적지·템플릿·캡처를 바꿀 수 없음
- temp는 그것을 캡처한 step **뒤**에서만 읽을 수 있고, 필드 이름과 겹칠 수 없음 (서명 전 검사)
- `derive` 출력은 taint 검사로 비밀을 되돌릴 수 없는 값만 허용
- 로그가 확인되지 않으면 아무것도 전송되지 않고, 로그는 멈춤(fail closed)
- 로그 체인은 노드 키로 서명되어 수정·삭제·순서 변경이 `verify`로 드러남. 로그에는 값이 없음(테스트로 확인)
- `unsafe` 금지, `unwrap`·`expect`·`panic`·인덱싱 금지 (clippy deny)

## 아직 보장하지 않는 것

- **TEE 미연동.** 지금 노드는 일반 프로세스. attestation, grant 봉인(HPKE), 재현 빌드가 다음 단계
- `Transport` 구현(TLS·스트림)은 아직 없음. 테스트용 가짜만 있음
- **레코드 롤백.** 운영자가 갱신 전 레코드를 다시 내밀어도 노드는 막지 못함(버전 카운터 필요)
- 스트림 세션은 호출 한 번으로 끝남. 연결을 유지한 채 여러 번 호출하는 세션은 없음
- SSH·DB 와이어 프로토콜·gRPC·WebSocket 프레이밍은 스크립트로 일부만 가능. SSH는 서명(`derive`)까지만
- 브라우저 로그인, 푸시 2FA, 하드웨어 키는 원리상 불가
- `json` 캡처는 serde_json 중간값을 거치며, 그 메모리는 zeroize되지 않음
- reflection 검사는 알려진 인코딩만 찾음. 서버가 다른 형태로 되돌려 주면 못 잡음
- 낮은 엔트로피 비밀의 해시는 taint상 허용되지만 무차별 대입으로 추측될 수 있음
- 로그 엔트리는 서명만 되고 암호화되지 않음. 경로·호스트가 로그 저장소에 보임
- 서버가 받은 값을 어떻게 쓰는지는 이 엔진의 범위 밖

## 개발

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
