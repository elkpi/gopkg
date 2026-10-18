package securelog

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

// Redact 移除 text 中 sensitive 值及其 base64/hex/URL/JSON 表示。
func Redact(text string, sensitive []string) string {
	for _, secret := range sensitive {
		if secret == "" {
			continue
		}
		variants := secretVariants(secret)
		for _, variant := range variants {
			if variant != "" && strings.Contains(text, variant) {
				text = strings.ReplaceAll(text, variant, "[REDACTED]")
			}
		}
	}
	return text
}

func secretVariants(secret string) []string {
	raw := []byte(secret)
	variants := []string{secret}
	if encoded := base64.StdEncoding.EncodeToString(raw); encoded != secret {
		variants = append(variants, encoded)
	}
	if encoded := base64.RawStdEncoding.EncodeToString(raw); encoded != secret {
		variants = append(variants, encoded)
	}
	if encoded := hex.EncodeToString(raw); len(raw) >= 4 {
		variants = append(variants, encoded)
	}
	if quoted, err := json.Marshal(secret); err == nil {
		variants = append(variants, string(quoted))
	}
	if escaped := url.QueryEscape(secret); escaped != secret {
		variants = append(variants, escaped)
	}
	if escaped := url.PathEscape(secret); escaped != secret {
		variants = append(variants, escaped)
	}
	return variants
}

// SensitiveFromKey 返回需要脱敏的密钥表示集合。
func SensitiveFromKey(secret string, raw []byte) []string {
	variants := secretVariants(secret)
	if len(raw) > 0 {
		variants = append(variants, hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw))
	}
	return variants
}
