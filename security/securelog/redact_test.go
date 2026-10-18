package securelog_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/elkpi/gopkg/security/securelog"
)

func TestRedactsSecretRepresentations(t *testing.T) {
	secret := "SYNTHETIC_SECRET_NOT_FOR_DEPLOYMENT"
	got := securelog.Redact("token="+secret, []string{secret})
	if strings.Contains(got, secret) {
		t.Fatal("泄露测试秘密")
	}
}

func TestRedactsEscapedAndEncodedForms(t *testing.T) {
	secret := `SYN"THETIC\SECRET`
	raw, _ := json.Marshal(secret)
	text := "body " + string(raw) + " tail " + url.QueryEscape(secret)
	got := securelog.Redact(text, []string{secret})
	if strings.Contains(got, "SYN") {
		t.Fatalf("转义/URL形式未脱敏：%s", got)
	}
}

func TestRedactsEncodedSecretBytes(t *testing.T) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	secret := base64.StdEncoding.EncodeToString(private[:])
	text := base64.StdEncoding.EncodeToString([]byte(secret)) + " " + hex.EncodeToString([]byte(secret)) + " " + hex.EncodeToString(private[:])
	got := securelog.Redact(text, []string{secret})
	if strings.Contains(got, secret[:8]) {
		t.Fatalf("密钥编码形式未脱敏：%s", got)
	}
}

func TestRedactKeepsUnrelatedText(t *testing.T) {
	got := securelog.Redact("正常日志内容 connection reset", []string{"SECRET"})
	if got != "正常日志内容 connection reset" {
		t.Fatalf("无关内容被修改：%s", got)
	}
}
