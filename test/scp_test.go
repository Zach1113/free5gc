package test_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"test"
	"test/consumerTestdata/UDM/TestGenAuthData"

	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/require"
)

const (
	scpBaseURL         = "http://127.0.0.6:8000"
	servingNetworkName = "5G:mnc093.mcc208.3gppnetwork.org"
	testAusfInstanceID = "00000000-0000-4000-8000-000000000000"
)

// TestSCPDirectProxy verifies the R17 direct-proxy paths from SCP to UDR, UDM,
// and AUSF. Each request exercises the real producer while entering through SCP.
func TestSCPDirectProxy(t *testing.T) {
	ue := test.NewRanUeContext(
		"imsi-208930000007487",
		1,
		nasMessage.AlgCiphering128NEA0,
		nasMessage.AlgIntegrity128NIA2,
		models.AccessType_3_GPP_ACCESS,
	)
	ue.AuthenticationSubs = test.GetAuthSubscription(
		TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP,
	)
	servingPlmnID := "20893"

	defer func() {
		test.DelUeFromMongoDB(t, ue, servingPlmnID)
		NfTerminate()
	}()

	test.DelUeFromMongoDB(t, ue, servingPlmnID)
	test.InsertUeToMongoDB(t, ue, servingPlmnID)

	t.Run("nudr-dr authentication subscription", func(t *testing.T) {
		resp, err := http.Get(scpBaseURL + "/nudr-dr/v2/subscription-data/" +
			ue.Supi + "/authentication-data/authentication-subscription")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var authSubs models.Udr_DR_AuthenticationSubscription
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&authSubs))
		require.Equal(t, ue.AuthenticationSubs.EncPermanentKey, authSubs.EncPermanentKey)
		require.Equal(t, ue.AuthenticationSubs.EncOpcKey, authSubs.EncOpcKey)
	})

	t.Run("nudm-ueau generate auth data", func(t *testing.T) {
		reqBody := models.Udm_UEAU_AuthenticationInfoRequest{
			ServingNetworkName: servingNetworkName,
			AusfInstanceId:     testAusfInstanceID,
		}
		resp := postJSON(t, scpBaseURL+"/nudm-ueau/v1/"+ue.Supi+
			"/security-information/generate-auth-data", reqBody)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var authInfo models.Udm_UEAU_AuthenticationInfoResult
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&authInfo))
		require.Equal(t, ue.Supi, authInfo.Supi)
		require.Equal(t, models.Udm_UEAU_AuthType_5_G_AKA, authInfo.AuthType)
		require.NotNil(t, authInfo.AuthenticationVector)
	})

	t.Run("nausf-auth ue authentication", func(t *testing.T) {
		reqBody := models.Ausf_UEAU_AuthenticationInfo{
			SupiOrSuci:         ue.Supi,
			ServingNetworkName: servingNetworkName,
		}
		resp := postJSON(t, scpBaseURL+"/nausf-auth/v1/ue-authentications", reqBody)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var authCtx models.Ausf_UEAU_UEAuthenticationCtx
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&authCtx))
		require.Equal(t, models.Ausf_UEAU_AuthType_5_G_AKA, authCtx.AuthType)
		require.Equal(t, servingNetworkName, authCtx.ServingNetworkName)
		require.NotEmpty(t, authCtx.Links["5g-aka"])
	})
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()

	payload, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	return resp
}
