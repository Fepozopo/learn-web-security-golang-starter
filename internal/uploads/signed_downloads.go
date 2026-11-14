package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

// CreateSignedDownloadPath returns a signed download URL valid for five minutes from now.
func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

// VerifySignedDownload reports whether the signature authorizes fileID and has not expired at now.
func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expires <= now.Unix() {
		return false
	}
	provided, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(signDownload(signingKey, fileID, expires))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

// signDownload returns the hexadecimal HMAC for a file ID and expiration timestamp.
func signDownload(signingKey [32]byte, fileID, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	return hex.EncodeToString(mac.Sum(nil))
}
