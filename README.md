# credentials

크리덴셜을 **운영자도 볼 수 없게** 보관하고, 쓸 때마다 **지울 수 없는 기록을 먼저 남긴 뒤** 쓰는 금고의 핵심 엔진.

## 구조

| 크레이트 | 역할 |
| --- | --- |
| `engine` | 비밀값 타입, 정책, 템플릿, 레코드 암호화, 호출자 서명, 선기록 로그, 응답 처리, 노드 |
| `verify` | 노드 로그를 독립적으로 검증하는 CLI (아래 참고) |

크리덴셜 종류와 프로토콜 흐름이 코드에 없다. 레코드는 **이름 붙은 필드 묶음**(바이트: 텍스트·이미지·키 파일 무엇이든)이다. 값을 어디에 어떻게 쓰는지, 누가 쓸 수 있는지는 기기가 서명한 정책 안에 적는다. 새 서비스를 붙일 때 코드를 고치지 않는다.

## 정책

```json
{
  "fields": [
    {"name": "client_id", "secret": false},
    {"name": "client_secret", "secret": true},
    {"name": "refresh_token", "secret": true},
    {"name": "access_token", "secret": true, "optional": true}
  ],
  "callers": [
    {"name": "billing-agent", "key": "<CallerPublicKey base64url>",
     "operations": ["refresh", "call"], "limit": {"count": 100, "window_ms": 60000}}
  ],
  "operations": [
    {"kind": "http", "name": "refresh",
     "destinations": [{"host": "auth.example.com", "port": 443}],
     "steps": [{
       "request": {"from": "fixed", "method": "POST", "path": "/oauth/token"},
       "inject": [{"target": {"kind": "body"},
                   "template": "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}&client_id={{pct(client_id)}}&client_secret={{pct(client_secret)}}"}],
       "capture": [{"source": {"from": "json", "pointer": "/access_token"},
                    "into": {"kind": "field", "name": "access_token"}}]
     }]},
    {"kind": "http", "name": "call",
     "destinations": [{"host": "*.api.example.com", "port": 443}],
     "methods": ["GET", "POST"], "paths": ["/v1/"], "caller_headers": ["Accept"],
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
| `derive` | 템플릿 출력을 호출자에게 돌려준다. 비밀이 **되돌릴 수 있는 형태로 섞여 있으면 서명 단계에서 거부**된다 |

- **호출자**: 정책에 `callers`(이름, 공개키, 쓸 수 있는 operation, 호출 한도)가 반드시 있다. 호출마다 `CallerKey::authorize`로 만든 `Authorization`이 필요하다. 서명 대상은 노드 키, 레코드(소유자·id·세대), operation, 요청 다이제스트, 시각, 1회용 nonce다. 노드는 ±5분을 벗어난 서명과 재사용된 nonce를 거부하고, 로그 엔트리에 호출자 이름을 남긴다.
- **호출자 요청의 범위**: `destinations`(`*.example.com`은 정확히 한 단계 라벨), `methods`, `paths`(경로 접두사, 세그먼트 경계 기준), `caller_headers`(허용 헤더 목록, 기본은 없음). `..`·`.` 세그먼트, `%2e`·`%2f`·`%5c`, `\`가 든 경로는 거부한다. 서버의 해석을 바꾸는 헤더(`Accept-Encoding`, `Range`, `TE`, `Expect`, `X-HTTP-Method-Override` 등)는 누구도 넣을 수 없고, 엔진이 `Accept-Encoding: identity`를 붙인다.
- **주입 대상**: `header` · `query` · `path_param` · `body` 넷뿐이고 나머지는 전부 템플릿이다.
- **캡처 소스**: `status` · `header` · `header_param`(`scheme`으로 `Digest` 같은 challenge 지정) · `cookie` · `json`(JSON pointer, 숫자는 쓰인 그대로) · `between` · `all`. stream에서는 `between`·`all`만 쓴다. 캡처 값은 64 KiB, 한 operation의 temp 합계는 1 MiB까지다.
- **캡처 저장처**:
  - `field`: **비밀 필드에만**, **`fixed` 요청이나 stream 스크립트에서만** 저장할 수 있다. 노드는 로그에 `update`를 남긴 뒤 한 세대 뒤의 새 레코드로 다시 봉인해 돌려준다. 뒤 step이 실패해도 새 레코드는 돌려준다.
  - `temp`: 같은 operation의 뒤 step만 읽는 값이다(세션 쿠키, challenge nonce).
- **mTLS**: `http`·`stream`에 `"identity": {"cert": "{{cert}}", "key": "{{key}}"}`를 두면 클라이언트 인증서가 `Transport`에만 전달된다.
- **정책 오류**는 위치와 규칙을 알려 준다. 예: `policy invalid at operations[0].steps[1].inject[2]: header must be a token, not reserved, and set once`. 서명 전에 `Policy::summary()`로 정책을 사람이 읽을 수 있는 줄로 볼 수 있다.

## 템플릿

`{{ }}` 안에는 이름(필드나 temp; 숫자로 시작하거나 `-`를 포함해도 된다), 변수, 문자열 리터럴, 함수 호출, `+` 연결만 쓸 수 있다. 분기와 반복은 없다. `{{ }}` 밖의 글자는 `}}`까지 그대로 나간다(중첩 JSON 본문).

- **변수**: `$method` `$host` `$path` `$pathname` `$query` `$body` `$unix` `$unix_ms` `$boundary` `$nonce` `$input`(derive 전용). stream과 identity에서는 `$host` `$unix` `$unix_ms` `$nonce`만 쓴다.
- **기본 함수**(코드에 있는 건 이것뿐):

| 분류 | 함수 |
| --- | --- |
| 인코딩 | `b64` `b64raw` `b64url` `b64urlraw` `b64decode` `b32decode` `hex` `hexdecode` `pct` `pctdecode` `json` `pem` |
| 문자열 | `upper` `lower` `trim` `replace` `json_set` `canonical_query` `time` `len` `be16` `be32` `xor` |
| 해시·MAC | `md5` `sha1` `sha256` `sha512` `keccak256` `hmac_sha1` `hmac_sha256` `hmac_sha512` `pbkdf2_sha256` `totp` |
| 서명 | `ed25519_sign` `p256_sign` `p256_sign_der` `p384_sign` `k256_sign` `k256_sign_recoverable` `rsa_sign_pkcs1_sha256` `rsa_sign_pss_sha256` |
| 암호화 | `aes_gcm_encrypt` `aes_cbc_encrypt` |

- **분석** (정책 서명 전에 모든 템플릿에 적용):
  - *tainted*: 비밀을 되돌릴 수 있는 형태로 담은 값. 인코딩·문자열 함수는 유지, 해시·MAC·서명·TOTP·`len`은 제거.
  - 암호화는 키가 **비밀 필드(또는 그 해시)** 일 때만 taint를 없앤다. nonce·AAD에 비밀이 있거나, 고정 nonce로 비밀과 호출자 입력을 함께 암호화하면 tainted다. `xor(key, key)`처럼 모두가 아는 값은 비밀 키가 아니다.
  - *controlled*: 호출자나 서버가 고르는 값(`$input` `$body` `$query` `$path` `$pathname` `$method`, 캡처 값).
  - 비밀과 고른 값이 `replace`·`xor`·`json_set`의 비교 위치, 디코더, 숫자 인자, 키 인자에서 만나면 **거부**한다. 실패 여부나 길이로 비밀을 한 조각씩 알아내는 오라클이 되기 때문이다(`len(replace(key, $input, ""))` 등).
- **렌더링 예산** (operation 하나 기준): 생성 바이트 128 MiB, PBKDF2 1,000,000 라운드, 서명 32회. 넘으면 `Budget` 오류.

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
2. 레코드 세대가 노드가 본 것·소유자가 pin한 것보다 오래되지 않았는지 확인 (롤백 방지)
3. 정책 서명을 grant의 기기 키 중 하나로 검증
4. 호출자: 정책에 있는지, 이 operation을 쓸 수 있는지, 서명·시각·nonce, 호출 한도
5. 요청이 operation 안인지 확인, 레코드 복호화(AAD가 id·소유자·세대·서명된 정책을 묶음), 예산 안에서 템플릿 렌더링
6. 로그 엔트리를 sink가 확인해야 `Confirmed`가 생긴다. 이게 없으면 전송·연결 함수를 호출할 수 없다(타입으로 강제). HTTP는 요청마다, stream은 연결마다 엔트리 하나. 전송은 노드 잠금 밖에서 한다
7. 응답을 파싱: `1xx` 건너뜀, chunked 해제, `Content-Encoding`(identity 외)·`Content-Range`·chunked 외 전송 코딩·헤더 접기는 거부, 헤드 64 KiB·헤더 128개·전체 16 MiB 제한
8. 캡처로 필드가 바뀌면 `update` 엔트리를 남긴 뒤 재봉인. 다른 비밀을 담은 캡처 값은 거부
9. 캡처한 비밀을 지운 뒤(`[redacted]`: 원문, JSON 이스케이프, `\/`, 그리고 `\u` 이스케이프로 쓴 JSON 문자열 전체), 비밀이 남아 있으면 응답을 버린다(`Reflection`)
10. 결과(`done`: 상태 코드, 성공 여부)를 로그에 남김

호출자는 와이어 바이트가 아니라 파싱된 `Response`(`status()`, `header()`, `body()`, `log_seqs()`)를 받는다.

## 키·기기·노드 운영

- `DeviceKey`·`NodeKey`·`CallerKey`는 `to_bytes`/`from_bytes`로 저장·복원한다.
- **기기 추가**: 같은 user key로 다른 기기가 grant하면 기기가 추가된다. 다른 기기를 `DeviceKey::endorse`로 보증하고 `Node::add_device`로 등록할 수도 있다. user key가 다른 grant는 기존 grant를 대체한다.
- **정책 변경**: 기기에서 `Record::rewrap`으로 값은 그대로 두고 새 정책으로 다시 봉인한다(세대 +1). `DeviceKey::pin`으로 노드에 최소 세대를 알려 옛 레코드를 막는다.
- **재시작**: `Node::restore(key, sink, clock, entries)`는 sink의 엔트리로 체인을 이어 가고, 엔트리에 남은 세대로 롤백 하한을 복원한다. grant는 복원하지 않는다(다시 grant).
- **로그 멈춤**: sink가 확인하지 못하면 로그가 멈춘다. sink의 마지막 엔트리를 `Node::reconcile`에 넘기면 풀린다.
- **체크포인트**: `Node::checkpoint()`는 체인 머리를 서명한 `SignedHead`를 준다. 소유자에게 주거나 공개하면 뒤를 잘라 낸 로그가 드러난다.
- 노드는 `&self` 메서드만 있어 여러 스레드가 공유한다.

## verify

```sh
verify <log.jsonl> <node-public-key>                       # 체인 전체
verify <log.jsonl> <node-public-key> --head <head.json>    # 서명된 체크포인트에서 끝나는지
verify <log.jsonl> <node-public-key> --owner <owner>       # 한 소유자의 엔트리만 (owner_prev 체인)
```

파일을 스트림으로 읽고, 오류는 실제 줄 번호로 알려 준다.

## 보장하는 것

- `Secret`은 출력·복제·직렬화가 안 되고, drop 시 0으로 덮어씀. 외부 크레이트는 값을 읽을 수 없음 (`compile_fail` 문서 테스트)
- 비밀로 버퍼를 만드는 함수는 크기를 먼저 계산해 재할당으로 지워지지 않은 사본을 남기지 않음 (할당기 검사로 측정, 아래 표)
- 정책은 기기 서명 + 암호문 AAD로 이중으로 묶임. 운영자가 목적지·템플릿·캡처·호출자를 바꿀 수 없음
- 서명된 호출자만, 허용된 operation만, 한 번만, 한도 안에서 쓸 수 있음
- 롤백: 노드가 본 세대·소유자 pin보다 오래된 레코드는 거부
- `derive` 출력과 모든 템플릿은 taint·오라클 분석을 통과해야 서명됨
- 로그가 확인되지 않으면 아무것도 전송되지 않고, 로그는 멈춤(fail closed). 시계가 뒤로 가도 체인은 유효
- 로그 체인은 노드 키로 서명되어 수정·삭제·순서 변경이 `verify`로 드러남. 로그에는 값이 없음(테스트로 확인)
- `unsafe` 금지, `unwrap`·`expect`·`panic`·인덱싱 금지 (clippy deny)

## 실측

같은 기기에서 release 빌드로 측정했다. 해커 에이전트의 측정 코드를 이전 코드(`79a21c1`)와 현재 코드에 똑같이 돌린 결과다. 메모리는 측정용 할당기로 잰 최대 사용량이다.

| 공격 | 이전 | 현재 |
| --- | --- | --- |
| 64 KiB 토큰 캡처 + 8 MiB 응답 (redaction·reflection 탐색) | 63.88 s | 0.08 s |
| 16 KiB 토큰 + 4 MiB 응답 | 6.34 s | 0.07 s |
| 템플릿 연결 ×401, 입력 1 MiB | 성공, 803 MiB | `Budget` 오류, 129 MiB |
| `hex` 16단 중첩, 입력 1 KiB | 성공, 96 MiB | `Budget` 오류, 96 MiB |
| PBKDF2 100만 라운드 ×127 | 12.70 s | 0.09 s 후 `Budget` 오류 |
| 64 MiB 응답 (캡처 없음) | 1.81 s 후 그대로 전달 | 0.02 s, `TooLarge` |
| 16 MiB JSON 배열 + pointer | 400 MiB | 64 MiB |
| 16 MiB 헤더 (330만 줄) | 192 MiB | 0 MiB, 헤드 64 KiB 초과로 거부 |
| 16 MiB 본문을 temp 16개에 캡처 | 768 MiB | 32 MiB, 64 KiB 초과로 거부 |
| 비밀이 지워지지 않고 해제된 메모리 블록 (json 캡처·`b64decode`·`json`·`replace`·`json_set`) | 1·8·1·1·1 | 0·0·0·0·0 |

## 아직 보장하지 않는 것

- **TEE 미연동.** 지금 노드는 일반 프로세스다. attestation, grant 봉인(HPKE), 재현 빌드가 다음 단계다. 그래서 `revoke`·`grant`를 부르는 쪽을 인증하지 않는다(노드 API에 접근하는 자가 grant를 지울 수 있다)
- `Transport` 구현(TLS·스트림)은 아직 없고, 테스트용 가짜만 있다
- ring의 RSA·P-384 키 구조체는 drop 시 zeroize되지 않는다
- 응답 본문을 한 번에 메모리에 올린다(최대 16 MiB). 스트리밍 본문은 아직 없다
- 서버가 캡처하게 한 값(다른 비밀을 담지 않은 것)은 서버가 정한다. 서버가 키 역할의 값을 내려 주면 그 키는 서버가 안다
- reflection 검사는 알려진 인코딩만 찾는다. 서버가 쪼개거나, 다른 방식으로 압축하거나, 암호화해서 되돌려 주면 못 잡는다. 4~7바이트 비밀 필드는 원문만, 8바이트 이상은 인코딩 형태까지 찾는다. 짧은 비밀은 응답에 우연히 같은 글자가 있어도 응답을 버린다
- 낮은 엔트로피 비밀의 해시는 분석상 허용되지만 무차별 대입으로 추측될 수 있다
- 로그 엔트리는 서명만 되고 암호화되지 않는다. 경로·호스트·호출자 이름이 로그 저장소에 보인다
- 롤백 하한은 노드가 본 세대와 pin으로만 정해진다. 한 번도 본 적 없는 노드에 옛 레코드를 처음 내밀면, pin이 없을 때는 막지 못한다
- 스트림 세션은 호출 한 번으로 끝난다. SSH·DB 와이어 프로토콜·gRPC·WebSocket 프레이밍은 스크립트로 일부만 가능하다
- 브라우저 로그인, 푸시 2FA, 하드웨어 키는 원리상 불가

## 개발

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

최소 Rust 버전은 1.87이다(`crypto-bigint` 0.7이 요구).
