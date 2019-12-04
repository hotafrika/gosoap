package gosoap

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"github.com/elgs/gostrgen"
	"time"
)

/*************************
	WS-Security types
*************************/
const (
	passwordType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	encodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)
//XMLName xml.Name `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
type security struct {
	//XMLName xml.Name  `xml:"wsse:Security"`
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
	Mustunderstand string `xml:"mustUnderstand,attr"`
	Auth wsAuth
	Timestamp Timestamp
}

type Timestamp struct {
	XMLName xml.Name  `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Timestamp"`
	Id string `xml:"Id,attr"`
	Created string    `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created"`
}

type password struct {
	//XMLName xml.Name `xml:"wsse:Password"`
	Type string `xml:"Type,attr"`
	Password string `xml:",chardata"`
}

type nonce struct {
	//XMLName xml.Name `xml:"wsse:Nonce"`
	Type string `xml:"EncodingType,attr"`
	Nonce string `xml:",chardata"`
}

type wsAuth struct {
	XMLName xml.Name  `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd UsernameToken"`
	Username string   `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Username"`
	Password password `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Password"`
	Nonce nonce      `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Nonce"`
	Created string    `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created"`
}
/*
<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" Id="Timestamp-28">
        <wsu:Created>2019-12-04T18:58:45Z</wsu:Created>
    </wsu:Timestamp>
    <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">j1JWogT+CwGIWqbjBLWEFqaXPq8=</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">MzEwMDI3MTQ1</wsse:Nonce>
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2019-12-04T18:58:45Z</wsu:Created>
    </wsse:UsernameToken>
</wsse:Security>
 */

func NewSecurity(username, passwd string) security {
	/** Generating Nonce sequence **/
	charsToGenerate := 32
	charSet := gostrgen.Lower | gostrgen.Digit

	nonceSeq, _ := gostrgen.RandGen(charsToGenerate, charSet, "", "")
	createdTime := time.Now().UTC().Format(time.RFC3339)
	auth := security{
		Auth:wsAuth{
			Username:username,
			Password:password {
				Type:passwordType,
				Password:generateToken(username, nonceSeq, createdTime, passwd),
			},
			Nonce:nonce {
				Type:encodingType,
				Nonce: nonceSeq,
			},
			Created: createdTime,
		},
		Timestamp:Timestamp{
			Id:      "Timestamp-28",
			Created: createdTime,
		},
		Mustunderstand: "1",
	}

	return auth
}

//Digest = B64ENCODE( SHA1( B64DECODE( Nonce ) + Date + Password ) )
func generateToken(Username string, Nonce string, Created string, Password string) string {

	sDec, _ := base64.StdEncoding.DecodeString(Nonce)


	hasher := sha1.New()
	//hasher.Write([]byte((base64.StdEncoding.EncodeToString([]byte(Nonce)) + Created.Format(time.RFC3339) + Password)))
	hasher.Write([]byte(string(sDec) + Created + Password))

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

