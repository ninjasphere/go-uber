// Package uber provides an api client for the Uber api.
// It exposes methods to get information about Uber products,
// estimates, times, and users.
//
// A lot of documentation will be pulled directly from
// https://developer.uber.com/v1/endpoints
package uber

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/skratchdot/open-golang/open"
)

const (
	Version          = "v1"
	ProductEndpoint  = "products"
	PriceEndpoint    = "estimates/price"
	TimeEndpoint     = "estimates/time"
	HistoryEndpoint  = "history"
	UserEndpoint     = "me"
	RequestsEndpoint = "requests"

	// the next two use `AUTH_EDPOINT`

	AccessCodeEndpoint  = "authorize"
	AccessTokenEndpoint = "token"

	State = "go-uber"
	Port  = ":7635"
)

// declared as vars so that unit tests can edit the values and hit internal test server
var (
	UberAPIHost = fmt.Sprintf("https://api.uber.com/%s", Version)
	AuthHost    = "https://login.uber.com/oauth"
)

// Client stores the tokens needed to access the Uber api.
// All methods of this package that hit said api are methods on this type.
type Client struct {
	// Your API token should be specified if your application will access the
	// Products, Price Estimates, and Time Estimates endpoints.
	serverToken string

	// OAuth 2.0 bearer token necessary for the use of the User Activity and
	// User Profile endpoints. It is the result of three step authentication
	// outlined in https://developer.uber.com/v1/auth/#oauth-2-0. When procuring
	// this token, keep in mind that you must specify the history scope if you
	// intend to use the User Activity endpoint and the profile scope if you
	// intend to use the User Profile endpoint.
	*Access

	// An http.Client is needed to make requests to the API as well as do the
	// authentication. Rather than instantiate a new client on each request, we
	// memoize it here, as it will always be used.
	HttpClient *http.Client

	// TODO(r-medina): add doc
	*auth
}

// NewClient creates a new client. The serverToken is your API token provided by Uber.
// When accessing a user's profile or activity a serverToken is not enough and an
// accessToken must be specified with the correct scope.
// To access those endpoints, use `*Client.OAuth()`
func NewClient(serverToken string) *Client {
	return &Client{
		serverToken: serverToken,
		Access:      new(Access),
		HttpClient:  new(http.Client),
	}
}

func (c *Client) SetAuth(clientID, clientSecret, redirect string) {
	c.auth = &auth{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirect,
	}
}

// OAuth begins the authorization process with Uber. There's no way to do this
// strictly programatically because of the multi-step OAuth process.  This method
// returns the URL that the user needs to go to in order for Uber to authorize your
// app and give you a authorization code.
func (c *Client) OAuth(scope ...string) (string, error) {

	return c.generateRequestURL(AuthHost, AccessCodeEndpoint, authReq{
		auth:         *c.auth,
		responseType: "code",
		scope:        strings.Join(scope, " "), // "profile history"
		state:        State,
	})
}

// AutOAuth automatically does the authorization flow by opening the user's browser,
// asking them to authorize, then booting up a server to deal with the user's redirect and
// authorizing your client.
func (c *Client) AutOAuth(scope ...string) error {
	urlString, err := c.OAuth(scope...)
	if err != nil {
		return nil
	}

	httpDone := make(chan struct{})
	httpErr := make(chan error)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state != State {
			httpErr <- fmt.Errorf("uber: evidence of tampering--incorrect state %s", state)
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			httpErr <- errors.New("uber: an unidentified error occured")
		}

		err = c.SetAccessToken(code)
		if err != nil {
			httpErr <- err
		}

		fmt.Fprintf(w, `<script type="text/javascript\">close()</script>
you may close this webpage`)
		close(httpDone)
	})

	go func() {
		httpErr <- http.ListenAndServe(Port, nil)
	}()

	err = open.Run(urlString)
	if err != nil {
		fmt.Printf("Failed to open browser. Go to this URL: %s", urlString)
	}

	select {
	case err := <-httpErr:
		return err
	case <-httpDone:
		return nil
	}
}

// SetAccessToken completes the third step of the authorization process.
// Once the user generates an authorization code
func (c *Client) SetAccessToken(authorizationCode string) error {
	return c.getToken(accReq{
		auth:         *c.auth,
		clientSecret: c.auth.clientSecret, // added here for safety
		grantType:    "authorization_code",
		code:         authorizationCode,
	})
}

// RefreshAccessToken uses the refresh token to get a new access token
func (c *Client) RefreshAccessToken() error {
	return c.getToken(accReq{
		auth:         *c.auth,
		clientSecret: c.auth.clientSecret, // added here for safety
		grantType:    "refresh_token",
		refreshToken: c.RefreshToken,
	})
}

func (c *Client) getToken(request accReq) error {
	payload, err := c.generateRequestURLHelper(reflect.ValueOf(request))
	if err != nil {
		return err
	}

	res, err := c.HttpClient.PostForm(
		fmt.Sprintf("%s/%s", AuthHost, AccessTokenEndpoint), payload,
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	decoder := json.NewDecoder(res.Body)

	if res.StatusCode == http.StatusOK {
		access := Access{}
		if err := decoder.Decode(&access); err != nil {
			return err
		}

		if access.TokenType == "Bearer" { // always true
			c.Access = &access
			return nil
		}
	}

	authErr := new(authError)
	decoder.Decode(authErr)
	return authErr
}

// GetProducts returns information about the Uber products offered at a
// given location. The response includes the display name and other details about
// each product, and lists the products in the proper display order.
// https://developer.uber.com/v1/endpoints/#product-types
func (c *Client) GetProducts(lat, lon float64) ([]*Product, error) {
	payload := productsReq{
		latitude:  lat,
		longitude: lon,
	}

	products := productsResp{}
	if err := c.get(ProductEndpoint, payload, false, &products); err != nil {
		return nil, err
	}

	return products.Products, nil
}

// GetPrices returns an estimated price range for each product offered at a given
// location. The price estimate is provided as a formatted string with the full price
// range and the localized currency symbol.
//
// The response also includes low and high estimates, and the ISO 4217 currency code
// for situations requiring currency conversion. When surge is active for a
// particular product, its surge_multiplier will be greater than 1, but the price
// estimate already factors in this multiplier.
// https://developer.uber.com/v1/endpoints/#price-estimates
func (c *Client) GetPrices(startLat, startLon, endLat, endLon float64) ([]*Price, error) {
	payload := pricesReq{
		startLatitude:  startLat,
		startLongitude: startLon,
		endLatitude:    endLat,
		endLongitude:   endLon,
	}

	prices := pricesResp{}
	if err := c.get(PriceEndpoint, payload, false, &prices); err != nil {
		return nil, err
	}

	return prices.Prices, nil
}

// GetTimes returns ETAs for all products offered at a given location, with the responses
// expressed as integers in seconds. We recommend that this endpoint be called every
// minute to provide the most accurate, up-to-date ETAs.
// The uuid and productID parameters can be empty strings. These provide
// additional experience customization.
func (c *Client) GetTimes(
	startLat, startLon float64, uuid, productID string,
) ([]*Time, error) {
	payload := timesReq{
		startLatitude:  startLat,
		startLongitude: startLon,
		customerUuid:   uuid,
		productID:      productID,
	}

	times := timesResp{}
	if err := c.get(TimeEndpoint, payload, false, &times); err != nil {
		return nil, err
	}

	return times.Times, nil
}

// GetUserActivity returns data about a user's lifetime activity with Uber. The response
// will include pickup locations and times, dropoff locations and times, the distance
// of past requests, and information about which products were requested.
func (c *Client) GetUserActivity(offset, limit int) (*UserActivity, error) {
	payload := historyReq{
		offset: offset,
		limit:  limit,
	}

	userActivity := new(UserActivity)
	if err := c.get(TimeEndpoint, payload, true, userActivity); err != nil {
		return nil, err
	}

	return userActivity, nil
}

// GetUserProfile returns information about the Uber user that has authorized with
// the application.
func (c *Client) GetUserProfile() (*User, error) {
	user := new(User)
	if err := c.get(UserEndpoint, nil, true, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (c *Client) CreateRequest(productID string, start *Location, end *Location, surgeConfirmationID string) (*Request, error) {
	payload := createRequestReq{
		ProductID:      productID,
		StartLatitude:  start.Latitude,
		StartLongitude: start.Longitude,
	}

	if end != nil {
		payload.EndLatitude = &end.Latitude
		payload.EndLongitude = &end.Longitude
	}

	if surgeConfirmationID != "" {
		payload.SurgeConfirmationID = &surgeConfirmationID
	}

	var request Request
	if err := c.post(RequestsEndpoint, payload, true, &request); err != nil {
		return nil, err
	}

	return &request, nil
}

func (c *Client) GetRequest(requestID string) (*Request, error) {
	request := new(Request)
	if err := c.get(RequestsEndpoint+"/"+requestID, nil, true, request); err != nil {
		return nil, err
	}

	return request, nil
}

func (c *Client) CancelRequest(requestID string) error {
	return c.delete(RequestsEndpoint+"/"+requestID, nil, true, nil)
}

// get helps facilitate all the get requests to the Uber api.
// Takes the endpoint, the query parameters, whether or not oauth should be used
// and the data structure that the JSON response should be unmarshalled into.
func (c *Client) get(
	endpoint string, payload uberAPIRequest, oauth bool, out interface{},
) error {
	url, err := c.generateRequestURL(UberAPIHost, endpoint, payload)
	if err != nil {
		return err
	}

	res, err := c.sendRequestWithAuthorization("GET", url, nil, oauth)
	if err != nil {
		return err
	}
	return c.readResponse(res, out)
}

func (c *Client) delete(
	endpoint string, payload uberAPIRequest, oauth bool, out interface{},
) error {
	url, err := c.generateRequestURL(UberAPIHost, endpoint, payload)
	if err != nil {
		return err
	}

	res, err := c.sendRequestWithAuthorization("DELETE", url, nil, oauth)
	if err != nil {
		return err
	}
	return c.readResponse(res, out)
}

// post helps facilitate all the post requests to the Uber api.
// Takes the endpoint, the payload, whether or not oauth should be used
// and the data structure that the JSON response should be unmarshalled into.
func (c *Client) post(
	endpoint string, payload uberAPIRequest, oauth bool, out interface{},
) error {

	url, err := c.generateRequestURL(UberAPIHost, endpoint, nil)
	if err != nil {
		return err
	}

	res, err := c.sendRequestWithAuthorization("POST", url, payload, oauth)
	if err != nil {
		return err
	}
	return c.readResponse(res, out)
}

func (c *Client) readResponse(res *http.Response, out interface{}) error {

	defer res.Body.Close()

	// If the status code is non-2xx, generate the error
	switch {
	case res.StatusCode == http.StatusNotFound:
		// should never, ever happen because we specify the endpoints
		return &uberError{
			Message: fmt.Sprintf("Endpoint not found."),
		}
	case res.StatusCode >= 300:
		// no good way to do this with `http.Status...` codes ;o
		uberErr := new(uberError)
		decoder := json.NewDecoder(res.Body)
		if err := decoder.Decode(uberErr); err != nil {
			return err
		}
		// the case where the Uber api didn't provide an UberError in the response
		if uberErr == (&uberError{}) {
			return errors.New("uber: an unidentified error occured")
		}
		return *uberErr
	}

	if out != nil {
		decoder := json.NewDecoder(res.Body)
		err := decoder.Decode(out)
		if err != nil {
			return err
		}
	}

	return nil
}

// sendRequestWithAuthorization sends an HTTP GET request with an Authorization
// field in the header containing the Client's access token (bearer token) if
// the oauth parameter is true and the server token (api token) if not.
func (c *Client) sendRequestWithAuthorization(method, url string, data uberAPIRequest, oauth bool) (*http.Response, error) {

	var body io.Reader
	if method == "POST" && data != nil {
		jsBody, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		body = bytes.NewReader(jsBody)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	auth := fmt.Sprintf("Token %s", c.serverToken)
	if oauth {
		auth = fmt.Sprintf("Bearer %s", c.Access.Token)
	}

	req.Header.Set("authorization", auth)

	return c.HttpClient.Do(req)
}

// generateRequestURL returns the appropriate a request url to the Uber api based on
// the specified endpoint and the data passed in
func (c *Client) generateRequestURL(
	base, endpoint string, data uberAPIRequest,
) (string, error) {
	var queryParameters string
	if data == nil {
		queryParameters = ""
	} else {
		payload, err := c.generateRequestURLHelper(reflect.ValueOf(data))
		if err != nil {
			return "", err
		}

		queryParameters = payload.Encode()
	}

	if queryParameters != "" {
		queryParameters = fmt.Sprintf("?%s", queryParameters)
	}

	return fmt.Sprintf("%s/%s%s", base, endpoint, queryParameters), nil
}

// generateRequestURLHelper recursively checks `val` to generate the payload. Should
// be used with caution. Only `Client.generateRequestURL` calls this.
func (c *Client) generateRequestURLHelper(val reflect.Value) (url.Values, error) {
	payload := make(url.Values)
	for i := 0; i < val.NumField(); i++ {
		fieldName := val.Type().Field(i).Name
		queryTag := strings.Split(val.Type().Field(i).Tag.Get("query"), ",")
		if queryTag[0] == "-" {
			continue
		}

		var v interface{}
		switch val.Field(i).Kind() {
		case reflect.Int:
			v = val.Field(i).Int()
		case reflect.Float64:
			v = val.Field(i).Float()
		case reflect.String:
			v = val.Field(i).String()
			if len(queryTag) > 1 && queryTag[1] == "required" {
				// cannot be required and empty
				if v == "" {
					return nil, fmt.Errorf("uber: %s is a required field", fieldName)
				}
			}
		case reflect.Struct:
			supPayload, err := c.generateRequestURLHelper(val.Field(i))
			if err != nil {
				return nil, err
			}
			// avoids nil field on struct (eg res)
			if len(supPayload) == 0 {
				continue
			}
			for k, va := range supPayload {
				payload.Add(k, va[0])
			}
		default:
			return nil, fmt.Errorf("%s is invalid", fieldName)
		}

		if v != "" && queryTag[0] != "" {
			payload.Add(queryTag[0], fmt.Sprintf("%v", v))
		}
	}

	return payload, nil
}

// uberAPIRequest is a shell data definition that is just used to document that
// `Client.generateRequestURL` takes a specific type of data
type uberAPIRequest interface{}

// TODO(r-medina): add doc
func (err uberError) Error() string {
	var uberErrBuff bytes.Buffer // because O(1) runtime, bitches
	uberErrBuff.WriteString(fmt.Sprintf("Uber API: %s", err.Message))

	// prints code if exists
	if err.Code != "" {
		uberErrBuff.WriteString(fmt.Sprintf("\nCode: %s", err.Code))
	}

	// prints erroneous fields
	if err.Fields != nil {
		uberErrBuff.WriteString("\nFields:")
		for k, v := range err.Fields {
			uberErrBuff.WriteString(fmt.Sprintf("\n\t%s: %v", k, v))
		}
	}

	return uberErrBuff.String()
}

// TODO(r-medina): add doc
func (err authError) Error() string {
	return fmt.Sprintf("Authentication: %s", err.ErrorString)
}
