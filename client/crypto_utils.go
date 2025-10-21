// Copyright 2025 snaart
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package phantomcore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	MaxSkip = 1000

	// ReplayWindowSeconds определяет временное окно (в секундах),
	// в течение которого сообщение считается действительным.
	// Сообщения старше этого значения будут отклонены.
	ReplayWindowSeconds = 300 // 5 минут

	// NonceCacheTTL определяет,
	// как долго nonce хранится в кэше перед удалением для экономии памяти.
	// Должно быть значительно больше, чем ReplayWindowSeconds.
	NonceCacheTTL = time.Hour * 1 // 1 час

	// ClockSkewAllowanceSeconds позволяет принимать сообщения,
	// временная метка которых немного опережает системные часы.
	// Это компенсирует небольшую рассинхронизацию часов между клиентами.
	ClockSkewAllowanceSeconds = 60 // 1 минута

	// NonceSize определяет размер (в байтах) криптографически случайного nonce.
	NonceSize = 16
)

var (
	errSkippedMessageKeyNotFound = errors.New("пропущенный ключ сообщения не найден")
	errReplayAttackNonceReuse    = errors.New("обнаружена replay-атака: nonce уже использовался")
	errMessageTooOld             = errors.New("сообщение слишком старое, возможно, replay-атака")
	errMessageFromFuture         = errors.New("временная метка сообщения из будущего")
)

// DoubleRatchet содержит полное состояние протокола.
type DoubleRatchet struct {
	KyberS *kyber1024.PrivateKey
	KyberR *kyber1024.PublicKey
	ECS    *[32]byte
	ECSPub *[32]byte
	ECR    *[32]byte

	RK  []byte
	CKs []byte
	CKr []byte

	Ns uint64
	Nr uint64
	PN uint64

	MKSKIPPED map[string][]byte

	// ReceivedNonces - это кэш для отслеживания использованных nonce
	//  и предотвращения replay-атак.
	// Ключ - это nonce в виде hex-строки, значение - время получения.
	ReceivedNonces map[string]time.Time
}

// Zeroize безопасно очищает все чувствительные данные в структуре.
func (dr *DoubleRatchet) Zeroize() {
	if dr == nil {
		return
	}
	if dr.KyberS != nil {
		if marshaled, err := dr.KyberS.MarshalBinary(); err == nil {
			clear(marshaled)
		}
	}
	if dr.ECS != nil {
		clear(dr.ECS[:])
	}
	if dr.RK != nil {
		clear(dr.RK)
	}
	if dr.CKs != nil {
		clear(dr.CKs)
	}
	if dr.CKr != nil {
		clear(dr.CKr)
	}
	for key, mk := range dr.MKSKIPPED {
		if mk != nil {
			clear(mk)
		}
		delete(dr.MKSKIPPED, key)
	}
	// Очищаем и обнуляем кэш nonce
	for key := range dr.ReceivedNonces {
		delete(dr.ReceivedNonces, key)
	}
	dr.KyberS, dr.ECS, dr.ECSPub, dr.RK, dr.CKs, dr.CKr, dr.MKSKIPPED, dr.ReceivedNonces = nil, nil, nil, nil, nil, nil, nil, nil
}

type storedDoubleRatchet struct {
	KyberS         []byte               `json:"kyber_s"`
	KyberR         []byte               `json:"kyber_r"`
	ECS            []byte               `json:"ec_s"`
	ECSPub         []byte               `json:"ec_spub"`
	ECR            []byte               `json:"ec_r"`
	RK             []byte               `json:"rk"`
	CKs            []byte               `json:"cks"`
	CKr            []byte               `json:"ckr"`
	Ns             uint64               `json:"ns"`
	Nr             uint64               `json:"nr"`
	PN             uint64               `json:"pn"`
	MKSKIPPED      map[string][]byte    `json:"mkskipped"`
	ReceivedNonces map[string]time.Time `json:"received_nonces"`
}

func (dr *DoubleRatchet) MarshalJSON() ([]byte, error) {
	if dr.KyberS == nil || dr.KyberR == nil || dr.ECS == nil || dr.ECSPub == nil || dr.ECR == nil {
		return nil, errors.New("невозможно сериализовать рэтчет с nil ключами")
	}
	kyberSBytes, err := dr.KyberS.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kyberRBytes, err := dr.KyberR.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Перед сохранением очищаем кэш nonce от слишком старых записей,
	// чтобы не раздувать базу данных.
	now := time.Now()
	for key, ts := range dr.ReceivedNonces {
		if now.Sub(ts) > NonceCacheTTL {
			delete(dr.ReceivedNonces, key)
		}
	}

	// ReceivedNonces сохраняется для защиты от replay-атак после перезапуска.
	stored := storedDoubleRatchet{
		KyberS:         kyberSBytes,
		KyberR:         kyberRBytes,
		ECS:            dr.ECS[:],
		ECSPub:         dr.ECSPub[:],
		ECR:            dr.ECR[:],
		RK:             dr.RK,
		CKs:            dr.CKs,
		CKr:            dr.CKr,
		Ns:             dr.Ns,
		Nr:             dr.Nr,
		PN:             dr.PN,
		MKSKIPPED:      dr.MKSKIPPED,
		ReceivedNonces: dr.ReceivedNonces, // Сохраняем кэш
	}
	return json.Marshal(stored)
}

func (dr *DoubleRatchet) UnmarshalJSON(data []byte) error {
	var stored storedDoubleRatchet
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	kemScheme := kyber1024.Scheme()
	privKey, err := kemScheme.UnmarshalBinaryPrivateKey(stored.KyberS)
	if err != nil {
		return err
	}
	dr.KyberS = privKey.(*kyber1024.PrivateKey)
	pubKey, err := kemScheme.UnmarshalBinaryPublicKey(stored.KyberR)
	if err != nil {
		return err
	}
	dr.KyberR = pubKey.(*kyber1024.PublicKey)
	if len(stored.ECS) != 32 || len(stored.ECSPub) != 32 || len(stored.ECR) != 32 {
		return errors.New("неверная длина ключей X25519")
	}
	dr.ECS = (*[32]byte)(stored.ECS)
	dr.ECSPub = (*[32]byte)(stored.ECSPub)
	dr.ECR = (*[32]byte)(stored.ECR)
	dr.RK, dr.CKs, dr.CKr, dr.Ns, dr.Nr, dr.PN, dr.MKSKIPPED = stored.RK, stored.CKs, stored.CKr, stored.Ns, stored.Nr, stored.PN, stored.MKSKIPPED

	// Восстанавливаем кэш nonce из сохраненных данных.
	if stored.ReceivedNonces != nil {
		dr.ReceivedNonces = stored.ReceivedNonces
	} else {
		dr.ReceivedNonces = make(map[string]time.Time)
	}

	return nil
}

// RatchetHeader теперь включает Nonce и Timestamp для защиты от replay-атак.
type RatchetHeader struct {
	KyberPublicKey    []byte `json:"kyber_pk"`
	ECPublicKey       []byte `json:"ec_pk"`
	PN                uint64 `json:"pn"`
	N                 uint64 `json:"n"`
	RatchetCiphertext []byte `json:"ratchet_ct,omitempty"`
	Nonce             []byte `json:"nonce"`
	Timestamp         int64  `json:"timestamp"`
}

type InitialCiphertexts struct {
	IKCiphertext         []byte `json:"ik_ct"`
	SPKCiphertext        []byte `json:"spk_ct"`
	OPKCiphertext        []byte `json:"opk_ct,omitempty"`
	OPKID                uint32 `json:"opk_id,omitempty"`
	RatchetCiphertext    []byte `json:"ratchet_ct"`
	EphemeralECPublicKey []byte `json:"e_ec_pk"`
}

func RatchetInitAlice(
	theirIdentityKeyKyber *kyber1024.PublicKey, theirIdentityKeyX25519 *[32]byte,
	theirSignedPreKeyKyber *kyber1024.PublicKey, theirSignedPreKeyX25519 *[32]byte,
	theirOneTimePreKeyKyber *kyber1024.PublicKey, theirOneTimePreKeyX25519 *[32]byte,
	theirOneTimePreKeyID uint32,
) (*DoubleRatchet, *InitialCiphertexts, error) {
	kemScheme := kyber1024.Scheme()
	_, aliceEphemeralPrivKyber, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	aliceEphemeralPrivEC, aliceEphemeralPubEC, err := generateECKeyPair()
	if err != nil {
		return nil, nil, err
	}
	ctIk, ssIkKem, err := kemScheme.Encapsulate(theirIdentityKeyKyber)
	if err != nil {
		return nil, nil, err
	}
	ssIkEcdh, err := curve25519.X25519(aliceEphemeralPrivEC[:], theirIdentityKeyX25519[:])
	if err != nil {
		return nil, nil, err
	}
	ssIk := append(ssIkEcdh, ssIkKem...)
	ctSpk, ssSpkKem, err := kemScheme.Encapsulate(theirSignedPreKeyKyber)
	if err != nil {
		return nil, nil, err
	}
	ssSpkEcdh, err := curve25519.X25519(aliceEphemeralPrivEC[:], theirSignedPreKeyX25519[:])
	if err != nil {
		return nil, nil, err
	}
	ssSpk := append(ssSpkEcdh, ssSpkKem...)

	var ssOpk []byte
	var ctOpk []byte
	if theirOneTimePreKeyKyber != nil && theirOneTimePreKeyX25519 != nil {
		var ssOpkKem []byte
		ctOpk, ssOpkKem, err = kemScheme.Encapsulate(theirOneTimePreKeyKyber)
		if err != nil {
			return nil, nil, err
		}
		ssOpkEcdh, err := curve25519.X25519(aliceEphemeralPrivEC[:], theirOneTimePreKeyX25519[:])
		if err != nil {
			return nil, nil, err
		}
		ssOpk = append(ssOpkEcdh, ssOpkKem...)
	}

	sk := kdfInitial(ssIk, ssSpk, ssOpk)
	ctRatchet, ssRatchetKem, err := kemScheme.Encapsulate(theirSignedPreKeyKyber)
	if err != nil {
		return nil, nil, err
	}
	ssRatchetEcdh, err := curve25519.X25519(aliceEphemeralPrivEC[:], theirSignedPreKeyX25519[:])
	if err != nil {
		return nil, nil, err
	}
	ssRatchet := append(ssRatchetEcdh, ssRatchetKem...)
	initialCts := &InitialCiphertexts{
		IKCiphertext: ctIk, SPKCiphertext: ctSpk, OPKCiphertext: ctOpk,
		OPKID: theirOneTimePreKeyID, RatchetCiphertext: ctRatchet, EphemeralECPublicKey: aliceEphemeralPubEC[:],
	}
	rk, cks := kdfRK(sk, ssRatchet)
	ratchet := &DoubleRatchet{
		KyberS:         aliceEphemeralPrivKyber.(*kyber1024.PrivateKey),
		KyberR:         theirSignedPreKeyKyber,
		ECS:            aliceEphemeralPrivEC,
		ECSPub:         aliceEphemeralPubEC,
		ECR:            theirSignedPreKeyX25519,
		RK:             rk,
		CKs:            cks,
		CKr:            nil,
		Ns:             0,
		Nr:             0,
		PN:             0,
		MKSKIPPED:      make(map[string][]byte),
		ReceivedNonces: make(map[string]time.Time),
	}
	return ratchet, initialCts, nil
}

func RatchetInitBob(
	ourIdentityPrivKyber *kyber1024.PrivateKey, ourIdentityPrivX25519 *[32]byte,
	ourPreKeyPrivKyber *kyber1024.PrivateKey, ourPreKeyPrivX25519 *[32]byte,
	ourOneTimePreKeyPrivKyber *kyber1024.PrivateKey, ourOneTimePreKeyPrivX25519 *[32]byte,
	theirEphemeralKyberPub *kyber1024.PublicKey, theirEphemeralECPub *[32]byte,
	initialCts *InitialCiphertexts,
) (*DoubleRatchet, error) {
	kemScheme := kyber1024.Scheme()
	ssIkKem, err := kemScheme.Decapsulate(ourIdentityPrivKyber, initialCts.IKCiphertext)
	if err != nil {
		return nil, err
	}
	ssIkEcdh, err := curve25519.X25519(ourIdentityPrivX25519[:], theirEphemeralECPub[:])
	if err != nil {
		return nil, err
	}
	ssIk := append(ssIkEcdh, ssIkKem...)
	ssSpkKem, err := kemScheme.Decapsulate(ourPreKeyPrivKyber, initialCts.SPKCiphertext)
	if err != nil {
		return nil, err
	}
	ssSpkEcdh, err := curve25519.X25519(ourPreKeyPrivX25519[:], theirEphemeralECPub[:])
	if err != nil {
		return nil, err
	}
	ssSpk := append(ssSpkEcdh, ssSpkKem...)

	var ssOpk []byte
	if len(initialCts.OPKCiphertext) > 0 {
		if ourOneTimePreKeyPrivKyber == nil || ourOneTimePreKeyPrivX25519 == nil {
			return nil, errors.New("алиса использовала OPK, но у нас нет ключа")
		}
		ssOpkKem, err := kemScheme.Decapsulate(ourOneTimePreKeyPrivKyber, initialCts.OPKCiphertext)
		if err != nil {
			return nil, err
		}
		ssOpkEcdh, err := curve25519.X25519(ourOneTimePreKeyPrivX25519[:], theirEphemeralECPub[:])
		if err != nil {
			return nil, err
		}
		ssOpk = append(ssOpkEcdh, ssOpkKem...)
	}
	sk := kdfInitial(ssIk, ssSpk, ssOpk)
	ssRatchetKem, err := kemScheme.Decapsulate(ourPreKeyPrivKyber, initialCts.RatchetCiphertext)
	if err != nil {
		return nil, err
	}
	ssRatchetEcdh, err := curve25519.X25519(ourPreKeyPrivX25519[:], theirEphemeralECPub[:])
	if err != nil {
		return nil, err
	}
	ssRatchet := append(ssRatchetEcdh, ssRatchetKem...)
	rk, ckr := kdfRK(sk, ssRatchet)
	_, bobEphemeralPrivKyber, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	bobEphemeralPrivEC, bobEphemeralPubEC, err := generateECKeyPair()
	if err != nil {
		return nil, err
	}
	return &DoubleRatchet{
		KyberS:         bobEphemeralPrivKyber.(*kyber1024.PrivateKey),
		KyberR:         theirEphemeralKyberPub,
		ECS:            bobEphemeralPrivEC,
		ECSPub:         bobEphemeralPubEC,
		ECR:            theirEphemeralECPub,
		RK:             rk,
		CKs:            nil,
		CKr:            ckr,
		Ns:             0,
		Nr:             0,
		PN:             0,
		MKSKIPPED:      make(map[string][]byte),
		ReceivedNonces: make(map[string]time.Time), // Инициализация кэша
	}, nil
}

func (dr *DoubleRatchet) RatchetEncrypt(plaintext []byte, firstMessageCts *InitialCiphertexts) (serializedHeader []byte, ciphertext []byte, err error) {

	var header RatchetHeader
	kemScheme := kyber1024.Scheme()
	if dr.CKs == nil {
		dr.PN = dr.Ns
		dr.Ns = 0
		ct, ssKem, errKem := kemScheme.Encapsulate(dr.KyberR)
		if errKem != nil {
			return nil, nil, errKem
		}
		ssEcdh, errEc := curve25519.X25519(dr.ECS[:], dr.ECR[:])
		if errEc != nil {
			return nil, nil, errEc
		}
		ss := append(ssEcdh, ssKem...)
		rk, cks := kdfRK(dr.RK, ss)
		dr.RK = rk
		dr.CKs = cks
		pubKeyKyberBytes, _ := dr.KyberS.Public().MarshalBinary()
		header.KyberPublicKey, header.ECPublicKey, header.RatchetCiphertext = pubKeyKyberBytes, dr.ECSPub[:], ct
	} else {
		pubKeyKyberBytes, _ := dr.KyberS.Public().MarshalBinary()
		header.KyberPublicKey, header.ECPublicKey = pubKeyKyberBytes, dr.ECSPub[:]
	}

	cks, encryptionKey, _ := kdfCK(dr.CKs)
	dr.CKs = cks
	header.PN, header.N = dr.PN, dr.Ns

	// Генерируем и добавляем Nonce и Timestamp
	header.Nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, header.Nonce); err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать nonce: %w", err)
	}
	header.Timestamp = time.Now().Unix()

	if firstMessageCts != nil {
		fullHeader := struct {
			RatchetHeader
			InitialCiphertexts *InitialCiphertexts `json:"initial_cts,omitempty"`
		}{RatchetHeader: header, InitialCiphertexts: firstMessageCts}
		serializedHeader, err = json.Marshal(fullHeader)
	} else {
		serializedHeader, err = json.Marshal(header)
	}
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err = encryptAEAD(encryptionKey, plaintext, serializedHeader, dr.Ns)
	if err != nil {
		return nil, nil, err
	}
	dr.Ns++
	return serializedHeader, ciphertext, nil
}

func (dr *DoubleRatchet) RatchetDecrypt(headerData []byte, ciphertext []byte) ([]byte, error) {
	var header RatchetHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		var headerWithInitialCts struct {
			RatchetHeader
			InitialCiphertexts *InitialCiphertexts `json:"initial_cts,omitempty"`
		}
		if err2 := json.Unmarshal(headerData, &headerWithInitialCts); err2 != nil {
			return nil, err // Возвращаем исходную ошибку парсинга
		}
		header = headerWithInitialCts.RatchetHeader
	}

	// =========================================================
	// ШАГ 1: Защита от Replay-атак
	// =========================================================
	now := time.Now()

	// 1.1: Проверка временной метки
	if header.Timestamp < now.Unix()-ReplayWindowSeconds {
		return nil, errMessageTooOld
	}
	if header.Timestamp > now.Unix()+ClockSkewAllowanceSeconds {
		return nil, errMessageFromFuture
	}

	// 1.2: Проверка Nonce
	if len(header.Nonce) == 0 {
		return nil, errors.New("сообщение не содержит nonce")
	}
	nonceKey := base64.StdEncoding.EncodeToString(header.Nonce) // Используем base64 для ключа карты

	if dr.ReceivedNonces == nil { // На всякий случай, если состояние было создано без конструктора
		dr.ReceivedNonces = make(map[string]time.Time)
	}

	if _, exists := dr.ReceivedNonces[nonceKey]; exists {
		return nil, errReplayAttackNonceReuse
	}

	// 1.3: Сохранение nonce и очистка старых
	dr.ReceivedNonces[nonceKey] = now
	for key, ts := range dr.ReceivedNonces {
		if now.Sub(ts) > NonceCacheTTL {
			delete(dr.ReceivedNonces, key)
		}
	}

	// =========================================================
	// ШАГ 2: Основная логика Double Ratchet
	// =========================================================
	plaintext, err := dr.trySkippedMessageKeys(header, headerData, ciphertext)
	if err == nil {
		return plaintext, nil
	}
	if !errors.Is(err, errSkippedMessageKeyNotFound) {
		return nil, err // Произошла реальная ошибка, а не просто ключ не найден
	}

	currentPubKeyKyberBytes, err := dr.KyberR.MarshalBinary()
	if err != nil {
		return nil, err
	}
	currentPubKeyECBytes := dr.ECR[:]
	if !bytes.Equal(header.KyberPublicKey, currentPubKeyKyberBytes) || !bytes.Equal(header.ECPublicKey, currentPubKeyECBytes) {
		if err := dr.skipMessageKeys(header.PN); err != nil {
			return nil, err
		}
		if err := dr.dhRatchetStep(header); err != nil {
			return nil, err
		}
	}

	if err := dr.skipMessageKeys(header.N); err != nil {
		return nil, err
	}
	if dr.CKr == nil {
		return nil, errors.New("цепочка получения не инициализирована")
	}
	ckr, encryptionKey, _ := kdfCK(dr.CKr)
	dr.CKr = ckr

	plaintext, err = decryptAEAD(encryptionKey, ciphertext, headerData, header.N)
	if err != nil {
		return nil, err
	}
	dr.Nr++
	return plaintext, nil
}

func (dr *DoubleRatchet) dhRatchetStep(header RatchetHeader) error {
	dr.PN, dr.Ns, dr.Nr, dr.MKSKIPPED = dr.Ns, 0, 0, make(map[string][]byte)
	kemScheme := kyber1024.Scheme()
	pk, err := kemScheme.UnmarshalBinaryPublicKey(header.KyberPublicKey)
	if err != nil {
		return err
	}
	dr.KyberR = pk.(*kyber1024.PublicKey)
	if len(header.ECPublicKey) != 32 {
		return errors.New("неверная длина ключа X25519")
	}
	dr.ECR = (*[32]byte)(header.ECPublicKey)
	if len(header.RatchetCiphertext) == 0 {
		return errors.New("в заголовке отсутствует шифротекст KEM")
	}
	ssKem, err := kemScheme.Decapsulate(dr.KyberS, header.RatchetCiphertext)
	if err != nil {
		return err
	}
	ssEcdh, err := curve25519.X25519(dr.ECS[:], dr.ECR[:])
	if err != nil {
		return err
	}
	ss := append(ssEcdh, ssKem...)
	rk, ckr := kdfRK(dr.RK, ss)
	dr.RK = rk
	dr.CKr = ckr
	_, newKyberPriv, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	newECPriv, newECPub, err := generateECKeyPair()
	if err != nil {
		return err
	}
	dr.KyberS = newKyberPriv.(*kyber1024.PrivateKey)
	dr.ECS, dr.ECSPub, dr.CKs = newECPriv, newECPub, nil
	return nil
}

func (dr *DoubleRatchet) trySkippedMessageKeys(header RatchetHeader, headerData []byte, ciphertext []byte) ([]byte, error) {
	keyID := messageKeyID(header.KyberPublicKey, header.ECPublicKey, header.N)
	mk, found := dr.MKSKIPPED[keyID]
	if !found {
		return nil, errSkippedMessageKeyNotFound
	}
	plaintext, err := decryptAEAD(mk, ciphertext, headerData, header.N)
	if err != nil {
		return nil, err
	}
	delete(dr.MKSKIPPED, keyID)
	return plaintext, nil
}

func (dr *DoubleRatchet) skipMessageKeys(until uint64) error {
	if dr.CKr == nil || dr.Nr >= until {
		return nil
	}
	if dr.Nr+MaxSkip < until {
		return fmt.Errorf("слишком много пропущенных сообщений")
	}
	pubKeyKyberBytes, err := dr.KyberR.MarshalBinary()
	if err != nil {
		return err
	}
	pubKeyECBytes := dr.ECR[:]
	for dr.Nr < until {
		ckr, encryptionKey, _ := kdfCK(dr.CKr)
		dr.CKr = ckr
		keyID := messageKeyID(pubKeyKyberBytes, pubKeyECBytes, dr.Nr)
		dr.MKSKIPPED[keyID] = encryptionKey
		dr.Nr++
	}
	return nil
}

func kdfInitial(secrets ...[]byte) []byte {
	info := []byte("PhantomX3DH_Hybrid_KEM_ECDH")
	salt := make([]byte, 32)
	var ikmParts [][]byte
	for _, s := range secrets {
		if s != nil {
			ikmParts = append(ikmParts, s)
		}
	}
	ikm := bytes.Join(ikmParts, nil)
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	sk := make([]byte, 32)
	_, _ = io.ReadFull(hkdfReader, sk)
	return sk
}

func kdfRK(rk, dhOut []byte) (newRK, chainKey []byte) {
	info := []byte("PhantomRatchet_Hybrid")
	salt, ikm := rk, dhOut
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	derivedKeyMaterial := make([]byte, 64)
	_, _ = io.ReadFull(hkdfReader, derivedKeyMaterial)
	return derivedKeyMaterial[:32], derivedKeyMaterial[32:]
}

func kdfCK(ck []byte) (newCK, encryptionKey, authenticationKey []byte) {
	macEnc := hmac.New(sha256.New, ck)
	macEnc.Write([]byte{0x01}) // Константа для ключа шифрования
	encryptionKey = macEnc.Sum(nil)

	macAuth := hmac.New(sha256.New, ck)
	macAuth.Write([]byte{0x02}) // Константа для ключа аутентификации
	authenticationKey = macAuth.Sum(nil)

	macNext := hmac.New(sha256.New, ck)
	macNext.Write([]byte{0x03}) // Константа для следующего цепочечного ключа
	newCK = macNext.Sum(nil)
	return
}

func messageKeyID(kyberPublicKey, ecPublicKey []byte, n uint64) string {
	return fmt.Sprintf("%s:%s:%d", base64.StdEncoding.EncodeToString(kyberPublicKey), base64.StdEncoding.EncodeToString(ecPublicKey), n)
}

func GenerateHybridIdentityKeyPair() (diliPriv sign.PrivateKey, diliPub sign.PublicKey, kyberPriv *kyber1024.PrivateKey, kyberPub *kyber1024.PublicKey, ecPriv *[32]byte, ecPub *[32]byte, err error) {
	diliScheme := mode5.Scheme()
	diliPub, diliPriv, err = diliScheme.GenerateKey()
	if err != nil {
		return
	}
	kemScheme := kyber1024.Scheme()
	kyberPubInt, kyberPrivInt, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return
	}
	kyberPriv, kyberPub = kyberPrivInt.(*kyber1024.PrivateKey), kyberPubInt.(*kyber1024.PublicKey)
	ecPriv, ecPub, err = generateECKeyPair()
	return
}

func GenerateHybridPreKey() (*kyber1024.PrivateKey, *kyber1024.PublicKey, *[32]byte, *[32]byte, error) {
	kemScheme := kyber1024.Scheme()
	pubK, privK, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	privEC, pubEC, err := generateECKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return privK.(*kyber1024.PrivateKey), pubK.(*kyber1024.PublicKey), privEC, pubEC, nil
}

func generateECKeyPair() (*[32]byte, *[32]byte, error) {
	privKey := new([32]byte)
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return nil, nil, err
	}
	// Применение clamping согласно RFC 7748
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	pubKey := new([32]byte)
	curve25519.ScalarBaseMult(pubKey, privKey)
	return privKey, pubKey, nil
}

func encryptAEAD(key, plaintext, headerData []byte, n uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	binary.BigEndian.PutUint64(nonce[gcm.NonceSize()-8:], n)
	return gcm.Seal(nonce, nonce, plaintext, headerData), nil
}

func decryptAEAD(key, ciphertext, headerData []byte, n uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("шифротекст слишком короткий")
	}
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	expectedNonce := make([]byte, gcm.NonceSize())
	binary.BigEndian.PutUint64(expectedNonce[gcm.NonceSize()-8:], n)
	if subtle.ConstantTimeCompare(nonce, expectedNonce) != 1 {
		return nil, fmt.Errorf("ошибка nonce: получен %x, ожидался %x", nonce, expectedNonce)
	}
	return gcm.Open(nil, nonce, actualCiphertext, headerData)
}
