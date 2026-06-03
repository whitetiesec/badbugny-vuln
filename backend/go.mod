module badbugny

go 1.21

// Intentionally vulnerable dependency versions for SCA tool demos.
// DO NOT use these versions in real applications.
require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // deprecated, CVE-2020-26160
	github.com/gin-contrib/cors v1.3.0 // older, permissive defaults
	github.com/gin-gonic/gin v1.7.7 // CVE-2023-26125, CVE-2023-29401
	github.com/lib/pq v1.10.0
	github.com/satori/go.uuid v1.2.0 // CVE-2021-3538 (predictable UUIDs)
	gopkg.in/yaml.v2 v2.2.8 // CVE-2019-11254 (DoS)
)

// Force the vulnerable yaml version even though gin's transitive deps
// would otherwise pick a patched one.
replace gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.2

require (
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/golang/protobuf v1.3.3 // indirect
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/ugorji/go/codec v1.1.7 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	golang.org/x/sys v0.0.0-20200116001909-b77594299b42 // indirect
)
