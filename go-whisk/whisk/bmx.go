/*
 * Copyright 2015-2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package whisk

import (
    "net/http"
    "errors"
    "net/url"
    "github.com/openwhisk/openwhisk-client-go/whisk"
    "github.com/openwhisk/openwhisk-client-go/wski18n"
)

var BmxService = &BluemixService{}
type BluemixService struct {
    BmxClient *whisk.Client
    OwClient *whisk.Client
}

type BmxEndpointRequest struct {
}
type BmxEndpointResponse struct {
    BmxApi          string    `json:"cf_api_endpoint,omitempty"`
}

type BmxInfoRequest struct {
}
type BmxInfoResponse struct {
    BmxName         string    `json:"name,omitempty"`
    ApiVersion      string    `json:"api_version,omitempty"`
    AuthEndpoint    string    `json:"authorization_endpoint,omitempty"`
    TokenEndpoint   string    `json:"token_endpoint,omitempty"`
}

type AuthTokenRequest struct {
    UserName        string    `json:"username"`
    UserPassword    string    `json:"password"`
    GrantType       string    `json:"grant_type"`
    ResponseType    string    `json:"response_type"`
}
type AuthTokenRequestOptions struct {
    GrantType       string    `url:"grant_type,omitempty"`
    ResponseType    string    `url:"response_type,omitempty"`
}
type AuthTokenResponse struct {
    AccessToken     string    `json:"access_token"`
    Expiration      int32     `json:"expires_in"`
    RefreshToken    string    `json:"refresh_token"`
    JTI             string    `json:"jti"`
    Scope           string    `json:"scope`
    TokenType       string    `json:"token_type"`
}

type BmxNamespacesRequest struct {
    AccessToken     string    `json:"accessToken"`
    RefreshToken    string    `json:"refreshToken"`
}
type BmxNamespacesResponse struct {
    Subject         string    `json:"subject"`
    Namespaces      []BmxNamespaceResponse `json:"namespaces"`
}
type BmxNamespaceResponse struct {
    Name            string    `json:"name"`
    UUID            string    `json:"uuid"`
    Key             string    `json:"key"`
}

////////////////////
// Bmx Methods //
////////////////////

// Locate the Bluemix API host, which is the target of Bluemix specific requests
func (s *BluemixService) GetBmxApiHost(*BmxEndpointRequest) (*BmxEndpointResponse, *http.Response, error) {
    const route string = "bluemix/v2/info"

    routeUrl, err := url.Parse(route)
    if err != nil {
        whisk.Debug(whisk.DbgError,"url.Parse(%s) error: %s\n", route, err)
        return nil, nil, generateUrlParseError(route, err)
    }

    req, err := s.OwClient.NewRequestUrl("GET", routeUrl, nil, whisk.DoNotIncludeNamespaceInUrl, whisk.DoNotAppendOpenWhiskPathPrefix,
        whisk.EncodeBodyAsJson, whisk.NoAuth)
    if err != nil {
        whisk.Debug(whisk.DbgError, "http.NewRequestUrl(GET, %s, nil, DoNotIncludeNamespaceInUrl, AppendOpenWhiskPathPrefix, EncodeBodyAsJson, NoAuth) error: '%s'\n", routeUrl, err)
        return nil, nil, generateNewRequestUrlError(routeUrl, err)
    }

    respBmxEndpoint := new(BmxEndpointResponse)
    resp, err := s.OwClient.Do(req, &respBmxEndpoint, whisk.ExitWithErrorOnTimeout)
    if err != nil {
        whisk.Debug(whisk.DbgError, "s.client.Do() error - HTTP req %s; error '%s'\n", req.URL.String(), err)
        return nil, resp, err
    }

    return respBmxEndpoint, resp, err
}

// Retrieve the Bluemix information from the specified Bluemix environment
func (s *BluemixService) GetBmxInfo(bmxApiEndpoint string) (*BmxInfoResponse, *http.Response, error) {
    const route string = "v2/info"

    routeUrl, err := url.Parse(route)
    if err != nil {
        whisk.Debug(whisk.DbgError,"url.Parse(%s) error: %s\n", route, err)
        return nil, nil, generateUrlParseError(route, err)
    }

    req, err := s.BmxClient.NewRequestUrl("GET", routeUrl, nil, whisk.DoNotIncludeNamespaceInUrl, whisk.DoNotAppendOpenWhiskPathPrefix,
        whisk.EncodeBodyAsJson, whisk.NoAuth)
    if err != nil {
        whisk.Debug(whisk.DbgError, "http.NewRequestUrl(GET, %s, nil, DoNotIncludeNamespaceInUrl, DoNotAppendOpenWhiskPathPrefix, EncodeBodyAsJson, NoAuth) error: '%s'\n", routeUrl, err)
        return nil, nil, generateNewRequestUrlError(routeUrl, err)
    }

    respBmxInfo := new(BmxInfoResponse)
    resp, err := s.BmxClient.Do(req, &respBmxInfo, whisk.ExitWithErrorOnTimeout)
    if err != nil {
        whisk.Debug(whisk.DbgError, "s.client.Do() error - HTTP req %s; error '%s'\n", req.URL.String(), err)
        return nil, resp, err
    }

    return respBmxInfo, resp, err
}

// Retrieve the Bluemix information from the specified Bluemix environment
func (s *BluemixService) GetBmxAuthToken(requestAuthToken *AuthTokenRequest) (*AuthTokenResponse, *http.Response, error) {
    const route string = "oauth/token"

    routeUrl, err := url.Parse(route)
    if err != nil {
        whisk.Debug(whisk.DbgError,"url.Parse(%s) error: %s\n", route, err)
        return nil, nil, generateUrlParseError(route, err)
    }

    reqAuthTokenData := url.Values{}
    reqAuthTokenData.Set("username", requestAuthToken.UserName)
    reqAuthTokenData.Set("password", requestAuthToken.UserPassword)
    reqAuthTokenData.Set("grant_type", requestAuthToken.GrantType)
    reqAuthTokenData.Set("response_type", requestAuthToken.ResponseType)

    req, err := s.BmxClient.NewRequestUrl("POST", routeUrl, reqAuthTokenData, whisk.DoNotIncludeNamespaceInUrl,
        whisk.DoNotAppendOpenWhiskPathPrefix, whisk.EncodeBodyAsFormData, whisk.AuthRequired)
    if err != nil {
        whisk.Debug(whisk.DbgError, "http.NewRequestUrl(POST, %s, %+v, DoNotIncludeNamespaceInUrl, DoNotAppendOpenWhiskPathPrefix, EncodeBodyAsFormData, AuthRequired) error: '%s'\n", routeUrl, reqAuthTokenData, err)
        return nil, nil, generateNewRequestUrlError(routeUrl, err)
    }

    respAuthToken := new(AuthTokenResponse)
    resp, err := s.BmxClient.Do(req, &respAuthToken, whisk.ExitWithErrorOnTimeout)
    if err != nil {
        whisk.Debug(whisk.DbgError, "s.client.Do() error - HTTP req %s; error '%s'\n", req.URL.String(), err)
        return nil, resp, err
    }

    return respAuthToken, resp, err
}

func (s *BluemixService) GetBmxNamespaces(reqBmxNamespaces *BmxNamespacesRequest) (*BmxNamespacesResponse, *http.Response, error) {
    const route string = "bluemix/v2/authenticate"

    routeUrl, err := url.Parse(route)
    if err != nil {
        whisk.Debug(whisk.DbgError,"url.Parse(%s) error: %s\n", route, err)
        return nil, nil, generateUrlParseError(route, err)
    }

    req, err := s.OwClient.NewRequestUrl("POST", routeUrl, reqBmxNamespaces, whisk.DoNotIncludeNamespaceInUrl,
        whisk.DoNotAppendOpenWhiskPathPrefix, whisk.EncodeBodyAsJson, whisk.NoAuth)
    if err != nil {
        whisk.Debug(whisk.DbgError, "http.NewRequestUrl(POST, %s, %v, DoNotIncludeNamespaceInUrl, DoNotAppendOpenWhiskPathPrefix, EncodeBodyAsJson, NoAuth) error: '%s'\n", routeUrl, reqBmxNamespaces, err)
        return nil, nil, generateNewRequestUrlError(routeUrl, err)
    }

    respBmxNamespaces := new(BmxNamespacesResponse)
    resp, err := s.OwClient.Do(req, &respBmxNamespaces, whisk.ExitWithErrorOnTimeout)
    if err != nil {
        whisk.Debug(whisk.DbgError, "s.client.Do() error - HTTP req %s; error '%s'\n", req.URL.String(), err)
        return nil, resp, err
    }

    return respBmxNamespaces, resp, err
}

func generateUrlParseError(route string, err error) (error) {
    errStr := wski18n.T("Unable to parse URL '{{.route}}': {{.err}}",
        map[string]interface{}{"route": route, "err": err})
    return whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
}

func generateNewRequestUrlError(routeUrl *url.URL, err error) (error) {
    errMsg := wski18n.T("Unable to create HTTP request for GET '{{.route}}': {{.err}}",
        map[string]interface{}{"route": routeUrl, "err": err})
    return whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK, whisk.DISPLAY_MSG,
        whisk.NO_DISPLAY_USAGE)
}
