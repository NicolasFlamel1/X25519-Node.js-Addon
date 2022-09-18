// Header files
#include <cstring>
#include <new>
#include <node_api.h>
#include <tuple>

// X25519 namespace
namespace X25519 {

	// Header files
	#include "./X25519-NPM-Package-master/main.cpp"
}

using namespace std;


// Constants

// Operation failed
static napi_value OPERATION_FAILED;


// Function prototypes

// Secret key from Ed25519 secret key
static napi_value secretKeyFromEd25519SecretKey(napi_env environment, napi_callback_info arguments);

// Public key from Ed25519 public key
static napi_value publicKeyFromEd25519PublicKey(napi_env environment, napi_callback_info arguments);

// Shared secret key from secret key and public key
static napi_value sharedSecretKeyFromSecretKeyAndPublicKey(napi_env environment, napi_callback_info arguments);

// Uint8 array to buffer
static tuple<uint8_t *, size_t, bool> uint8ArrayToBuffer(napi_env environment, napi_value uint8Array);

// Buffer to uint8 array
static napi_value bufferToUint8Array(napi_env environment, uint8_t *data, size_t size);


// Main function

// Initialize module
NAPI_MODULE_INIT() {

	// Check if initializing operation failed failed
	if(napi_get_null(env, &OPERATION_FAILED) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}

	// Check if creating secret key from Ed25519 secret key property failed
	napi_value temp;
	if(napi_create_function(env, nullptr, 0, secretKeyFromEd25519SecretKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "secretKeyFromEd25519SecretKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating public key from Ed25519 public key property failed
	if(napi_create_function(env, nullptr, 0, publicKeyFromEd25519PublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "publicKeyFromEd25519PublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating hared secret key from secret key and public key property failed
	if(napi_create_function(env, nullptr, 0, sharedSecretKeyFromSecretKeyAndPublicKey, nullptr, &temp) != napi_ok || napi_set_named_property(env, exports, "sharedSecretKeyFromSecretKeyAndPublicKey", temp) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Check if creating operation failed property failed
	if(napi_set_named_property(env, exports, "OPERATION_FAILED", OPERATION_FAILED) != napi_ok) {
	
		// Return nothing
		return nullptr;
	}
	
	// Return exports
	return exports;
}


// Supporting function implementation

// Secret key from Ed25519 secret key
napi_value secretKeyFromEd25519SecretKey(napi_env environment, napi_callback_info arguments) {

	// Check if not enough arguments were provided
	size_t argc = 1;
	napi_value argv[argc];
	if(napi_get_cb_info(environment, arguments, &argc, argv, nullptr, nullptr) != napi_ok || argc != sizeof(argv) / sizeof(argv[0])) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting Ed25519 secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> ed25519SecretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(ed25519SecretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from Ed25519 secret key failed
	uint8_t secretKey[X25519::secretKeySize()];
	if(!X25519::secretKeyFromEd25519SecretKey(secretKey, get<0>(ed25519SecretKey), get<1>(ed25519SecretKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return secret key as a uint8 array
	return bufferToUint8Array(environment, secretKey, sizeof(secretKey));
}

// Public key from Ed25519 public key
napi_value publicKeyFromEd25519PublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if not enough arguments were provided
	size_t argc = 1;
	napi_value argv[argc];
	if(napi_get_cb_info(environment, arguments, &argc, argv, nullptr, nullptr) != napi_ok || argc != sizeof(argv) / sizeof(argv[0])) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting Ed25519 public key from arguments failed
	const tuple<uint8_t *, size_t, bool> ed25519PublicKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(ed25519PublicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from Ed25519 public key failed
	uint8_t publicKey[X25519::publicKeySize()];
	if(!X25519::publicKeyFromEd25519PublicKey(publicKey, get<0>(ed25519PublicKey), get<1>(ed25519PublicKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return public key as a uint8 array
	return bufferToUint8Array(environment, publicKey, sizeof(publicKey));
}

// Shared secret key from secret key and public key
napi_value sharedSecretKeyFromSecretKeyAndPublicKey(napi_env environment, napi_callback_info arguments) {

	// Check if not enough arguments were provided
	size_t argc = 2;
	napi_value argv[argc];
	if(napi_get_cb_info(environment, arguments, &argc, argv, nullptr, nullptr) != napi_ok || argc != sizeof(argv) / sizeof(argv[0])) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting secret key from arguments failed
	const tuple<uint8_t *, size_t, bool> secretKey = uint8ArrayToBuffer(environment, argv[0]);
	if(!get<2>(secretKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting public key from arguments failed
	const tuple<uint8_t *, size_t, bool> publicKey = uint8ArrayToBuffer(environment, argv[1]);
	if(!get<2>(publicKey)) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if getting shared secret key from secret key and public key failed
	uint8_t sharedSecretKey[X25519::sharedSecretKeySize()];
	if(!X25519::sharedSecretKeyFromSecretKeyAndPublicKey(sharedSecretKey, get<0>(secretKey), get<1>(secretKey), get<0>(publicKey), get<1>(publicKey))) {
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return shared secret key as a uint8 array
	return bufferToUint8Array(environment, sharedSecretKey, sizeof(sharedSecretKey));
}

// Uint8 array to buffer
tuple<uint8_t *, size_t, bool> uint8ArrayToBuffer(napi_env environment, napi_value uint8Array) {

	// Check if uint8 array isn't a typed array
	bool isTypedArray;
	if(napi_is_typedarray(environment, uint8Array, &isTypedArray) != napi_ok || !isTypedArray) {
	
		// Return failure
		return {nullptr, 0, false};
	}
	
	// Check if uint8 array isn't a uint8 array
	napi_typedarray_type type;
	size_t size;
	uint8_t *data;
	if(napi_get_typedarray_info(environment, uint8Array, &type, &size, reinterpret_cast<void **>(&data), nullptr, nullptr) != napi_ok || type != napi_uint8_array) {
	
		// Return failure
		return {nullptr, 0, false};
	}
	
	// Return data and size
	return {data, size, true};
}

// Buffer to uint8 array
napi_value bufferToUint8Array(napi_env environment, uint8_t *data, size_t size) {

	// Check if allocating memory for buffer failed
	uint8_t *buffer = new(nothrow) uint8_t[size];
	if(!buffer) {
	
		// Clear data
		memset(data, 0 size);
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if allocating memory for size hint failed
	size_t *sizeHint = new(nothrow) size_t(size);
	if(!sizeHint) {
	
		// Clear data
		memset(data, 0 size);
	
		// Free memory
		delete [] buffer;
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Copy data
	memcpy(buffer, data, size);
	
	// Clear data
	memset(data, 0 size);
	
	// Check if creating array buffer from data failed
	napi_value arrayBuffer;
	if(napi_create_external_arraybuffer(environment, buffer, size, [](napi_env environment, void *finalizeData, void *finalizeHint) {
	
		// Get buffer
		uint8_t *buffer = reinterpret_cast<uint8_t *>(finalizeData);
		
		// Get size hint
		const size_t *sizeHint = static_cast<size_t *>(finalizeHint);
		
		// Clear buffer
		memset(buffer, 0 *sizeHint);
		
		// Free memory
		delete [] buffer;
		delete sizeHint;
	
	}, sizeHint, &arrayBuffer) != napi_ok) {
	
		// Clear buffer
		memset(buffer, 0 size);
	
		// Free memory
		delete [] buffer;
		delete sizeHint;
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Check if creating uint8 array from array buffer failed
	napi_value uint8Array;
	if(napi_create_typedarray(environment, napi_uint8_array, size, arrayBuffer, 0, &uint8Array) != napi_ok) {
	
		// Clear buffer
		memset(buffer, 0 size);
	
		// Free memory
		delete [] buffer;
		delete sizeHint;
	
		// Return operation failed
		return OPERATION_FAILED;
	}
	
	// Return uint8 array
	return uint8Array;
}
