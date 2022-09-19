{
	"targets": [
		{
			"target_name": "X25519",
			"sources": [
				"./X25519-NPM-Package-master/crypto_hash_sha512.c",
				"./main.cpp",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/base.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_0.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_1.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_add.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_copy.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_cswap.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_frombytes.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_invert.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_mul.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_mul121666.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_sq.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_sub.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/fe_tobytes.c",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/scalarmult.c"
			],
			"include_dirs": [
				"./",
				"./X25519-NPM-Package-master/",
				"./supercop-20220213/crypto_scalarmult/curve25519/ref10/"
			],
			"defines": [
				"CRYPTO_NAMESPACE="
			]
		}
	]
}
