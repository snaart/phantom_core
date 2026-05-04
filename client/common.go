package phantomcore

const (
	// dbSaltMetadataKey - ключ для хранения соли шифрования БД в метаданных
	dbSaltMetadataKey = "db_encryption_salt"

	// Параметры Argon2id для KDF
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32

	// NumOPKs - количество One-Time Prekeys
	NumOPKs = 100

	// PIN check constants
	pinCheckConstant    = "phantom-pin-check-ok"
	pinCheckMetadataKey = "pin_check"
)
