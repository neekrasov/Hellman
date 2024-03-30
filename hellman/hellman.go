package hellman

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
)

const generator = 2

// Генерация публичного ключа -  w^x mod n = generator^privint mod prime
type Hellman struct {
	privateKey string   // секретный ключ который используется для DES и иммитовставок.
	publicKey  *big.Int // публичный ключ - для передачи на клиент/сервер для преобразования в приватный ключ.
	privint    int64    // число с помощью которого генерируем public key
	generator  int64    // основание степени - 2, работаем в поле (0,1).
	prime      *big.Int //
}

func New() (*Hellman, error) {
	privint, err := GenRandom(1024)
	if err != nil {
		return nil, err
	}

	prime := getPrime()
	publicKey := GenPubKey(big.NewInt(generator), big.NewInt(privint), prime)

	return &Hellman{
		publicKey: publicKey,
		privint:   privint,
		generator: generator,
		prime:     prime,
	}, nil
}

func (h *Hellman) PublicKey() *big.Int {
	return h.publicKey
}

// genSharedKey - вычисляет общий ключ
func (h *Hellman) genSharedKey(publicKey *big.Int) *big.Int {
	pubKey := new(big.Int)
	pubKey.Exp(publicKey, big.NewInt(h.privint), h.prime)
	return pubKey
}

// GenPrivateKey генерирует private ключ из public ключа.
func (h *Hellman) GenPrivateKey(publicKey *big.Int) (string, error) {
	sharedKey := h.genSharedKey(publicKey)
	privateKey, err := HashSHA256(sharedKey.String())
	if err != nil {
		return "", err
	}
	h.privateKey = privateKey
	return h.privateKey, nil
}

func HashSHA256(val string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("openssl", "dgst", "-sha256", "-hex")
	cmd.Stdin = strings.NewReader(val)
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	output := strings.TrimSpace(out.String())
	parts := strings.Split(output, " ")
	if len(parts) != 2 {
		return "", errors.New("unexpected output format")
	}

	return parts[1], nil
}

// 8192 bit prime taken from RFC: http://www.rfc-editor.org/rfc/rfc3526.txt  function to fetch the prime.
func getPrime() *big.Int {
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF", 16)
	return prime
}

// GenRandom генерирует случайное число заданной длины в битах.
func GenRandom(bits int) (int64, error) {
	// Вычисляем количество байтов, необходимых для хранения числа заданной длины в битах.
	randBytes := bits / 8
	if bits%8 != 0 {
		randBytes++ // Добавляем дополнительный байт, если количество бит не делится нацело на 8.
	}

	// Генерируем случайные байты.
	b := make([]byte, randBytes)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	// Преобразуем байты в целое число.
	randInt := int64(0)
	for _, v := range b {
		randInt = (randInt << 8) | int64(v)
	}

	return randInt, nil
}

// GenPubKey генерирует открытый ключ, используя заданные параметры.
func GenPubKey(generator *big.Int, privInt *big.Int, prime *big.Int) *big.Int {
	// Вычисляем g^(secret int) % prime
	pubKey := new(big.Int)
	pubKey.Exp(generator, privInt, prime)
	return pubKey
}

func DES3Encode(msg, key string) (string, error) {
	cmd := exec.Command("openssl", "enc", "-des3", "-a", "-pass", fmt.Sprintf("pass:%x", key))
	cmd.Stdin = strings.NewReader(msg)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func DES3Decode(msg, key string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("openssl", "enc", "-des3", "-d", "-a", "-pass", fmt.Sprintf("pass:%x", key))
	cmd.Stderr = &out
	cmd.Stdin = strings.NewReader(msg + "\n")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to decode key: %s, stderr: %s", err.Error(), out.String())
	}
	return strings.TrimSpace(string(output)), nil
}

func HashSHA256WithHMAC(val string, key string) (string, error) {
	cmd := exec.Command("openssl", "dgst", "-sha256", "-hmac", key, "-hex")
	cmd.Stdin = strings.NewReader(val)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	output := strings.TrimSpace(out.String())
	parts := strings.Split(output, " ")
	if len(parts) != 2 {
		return "", errors.New("unexpected output format")
	}

	return parts[1], nil
}

func VerifyHMAC(expectedHMAC, key, message string) (bool, error) {
	actualHMAC, err := HashSHA256WithHMAC(message, key)
	if err != nil {
		return false, err
	}

	if actualHMAC != expectedHMAC {
		return false, nil
	}
	return true, nil
}
