package api

// Passkey enrollment API (Batch 8).
//
// ENROLL_PASSKEY (admin) adds a credential to the domain's
// passkey store: the credential ID and the public key in JWK
// form, plus an opaque user handle and a label. Only public-key
// material is accepted; private keys are never involved.
// LIST_PASSKEYS (viewer) lists enrolled credentials (metadata
// and key type only; key values are not returned). REMOVE_PASSKEY
// (operator) deletes one credential by ID. All three require
// passkeys to be configured for the domain (enabled, RP ID,
// credentials file); otherwise they report ERR_INVALID_PARAM.
//
// The registration ceremony is not implemented: the operator
// obtains the credential ID and public key from the
// authenticator out of band (for example, from a WebAuthn
// registration performed against a trusted enrollment tool)
// and enrolls them here. See docs/configuration.md.

import (
	"sonushield/core/domains"
)

func enrollPasskeyResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string, string) {
	if domainSettings.Passkeys == nil {
		return nil, ERR_INVALID_PARAM, "passkeys are not configured for this domain"
	}
	cred := domains.PasskeyCredential{
		CredentialID: params["credentialId"],
		PublicKey: domains.PasskeyPublicKey{
			Kty: params["kty"],
			Crv: params["crv"],
			X:   params["x"],
			Y:   params["y"],
			N:   params["n"],
			E:   params["e"],
		},
		UserHandle: params["userHandle"],
		Label:      params["label"],
	}
	for key := range params {
		switch key {
		case "credentialId", "kty", "crv", "x", "y", "n", "e", "userHandle", "label":
		default:
			return nil, ERR_INVALID_PARAM, "unknown parameter " + key
		}
	}
	if err := domainSettings.Passkeys.Enroll(cred); err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	return map[string]interface{}{
		"ENROLLED":   cred.CredentialID,
		"CREDENTIALS": domainSettings.Passkeys.Count(),
	}, "", ""
}

func listPasskeysResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string) {
	for range params {
		return nil, ERR_INVALID_PARAM
	}
	credentials := []map[string]interface{}{}
	if domainSettings.Passkeys != nil {
		for _, cred := range domainSettings.Passkeys.List() {
			credentials = append(credentials, map[string]interface{}{
				"CREDENTIAL_ID": cred.CredentialID,
				"LABEL":         cred.Label,
				"USER_HANDLE":   cred.UserHandle,
				"SIGN_COUNT":    cred.SignCount,
				"KEY_TYPE":      cred.PublicKey.Kty,
				"CURVE":         cred.PublicKey.Crv,
			})
		}
	}
	return map[string]interface{}{
		"CREDENTIALS": credentials,
		"CONFIGURED":  domainSettings.Passkeys != nil,
	}, ""
}

func removePasskeyResponse(domainSettings *domains.DomainSettings, params map[string]string) (map[string]interface{}, string, string) {
	if domainSettings.Passkeys == nil {
		return nil, ERR_INVALID_PARAM, "passkeys are not configured for this domain"
	}
	for key := range params {
		if key != "credentialId" {
			return nil, ERR_INVALID_PARAM, "unknown parameter " + key
		}
	}
	credentialID := params["credentialId"]
	if credentialID == "" {
		return nil, ERR_PARAMS_REQUIRED, ""
	}
	if err := domainSettings.Passkeys.Remove(credentialID); err != nil {
		return nil, ERR_INVALID_PARAM, err.Error()
	}
	return map[string]interface{}{
		"REMOVED":     credentialID,
		"CREDENTIALS": domainSettings.Passkeys.Count(),
	}, "", ""
}
