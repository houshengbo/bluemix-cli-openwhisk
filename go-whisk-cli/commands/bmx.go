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

package commands

import (
    "errors"
    "fmt"

    "../../go-whisk/whisk"
    "../wski18n"

    "github.com/fatih/color"
    "github.com/spf13/cobra"
    "net/http"
    "net/url"
    "strconv"
)

var bmxflags struct {
    username   string
    password   string
    namespace  string
}


//////////////
// Commands //
//////////////

var bmxCmd = &cobra.Command{
    Use:   "bluemix",
    Short: wski18n.T("bluemix integration"),
}

var bmxLoginCmd = &cobra.Command{
    Use:           "login --user BMX_USER_NAME --password BMX_USER_PASSWORD [--namespace NAMESPACE]",
    Short:         wski18n.T("login to Bluemix"),
    SilenceUsage:  true,
    SilenceErrors: true,
    PreRunE:       setupOpenWhiskClientConfig,
    RunE: func(cmd *cobra.Command, args []string) error {

        // 0. Validate command arguments
        whisk.Debug(whisk.DbgInfo, "bmxflags: %+v\n", bmxflags)
        if !(cmd.LocalFlags().Changed("user") && cmd.LocalFlags().Changed("password")) {
            errMsg := wski18n.T("User name and/or password were not specified")
            whiskErr := whisk.MakeWskError(errors.New(errMsg), whisk.EXITCODE_ERR_NETWORK, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }

        // 1. Query OpenWhisk for the Bluemix API endpoint
        reqBmxEndpoint := new(whisk.BmxEndpointRequest)
        respBmxEndpoint, _, err := whisk.BmxService.GetBmxApiHost(reqBmxEndpoint)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxApiHost(%#v, false) error: %s\n", reqBmxEndpoint, err)
            return generateBluemixApiHostAccessError(err)
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix API: %s\n", respBmxEndpoint.BmxApi)
        whisk.BmxService.BmxClient, err = setupBmxClientConfig(respBmxEndpoint.BmxApi)
        if err != nil {
            whisk.Debug(whisk.DbgError, "setupBmxClientConfig(%s) error: %s\n", respBmxEndpoint.BmxApi, err)
            return generateBluemixApiHostAccessError(err)
        }

        // 2. Query the Bluemix API endpoint for the Bluemix UAA endpoint
        bmxApiUrl := fmt.Sprintf("https://%s/v2/info", respBmxEndpoint.BmxApi)
        respBmxInfo, _, err := whisk.BmxService.GetBmxInfo(bmxApiUrl)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxInfo(%s) error: %s\n", bmxApiUrl, err)
            return generateBluemixAuthEndpointAccessError(err)
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix authorization endpoint: %s\n", respBmxInfo.AuthEndpoint)
        whisk.BmxService.BmxClient, err = setupBmxClientConfig(respBmxInfo.AuthEndpoint)
        if err != nil {
            whisk.Debug(whisk.DbgError, "setupBmxClientConfig(%s) error: %s\n", respBmxEndpoint.BmxApi, err)
            return generateBluemixAuthEndpointAccessError(err)
        }

        // 3. Query the Bluemix UAA endpoint for the user's Bluemix access/bearer token
        whisk.Debug(whisk.DbgInfo, "Bluemix client baseURL: %s\n", whisk.BmxService.BmxClient.BaseURL)
        reqAuthToken := &whisk.AuthTokenRequest{
            UserName: bmxflags.username,
            UserPassword: bmxflags.password,
            GrantType: "password",
            ResponseType: "token",
        }
        respAuthToken, _, err := whisk.BmxService.GetBmxAuthToken(reqAuthToken)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxAuthToken(%s) error: %s\n", respBmxInfo.AuthEndpoint, err)
            errMsg := wski18n.T("Unable to authenticate with Bluemix: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
                whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix access token: %#v\n", respAuthToken)

        // 4. Retrieve the namespaces associated with this login
        reqNamespaces := &whisk.BmxNamespacesRequest{
            AccessToken: respAuthToken.AccessToken,
            RefreshToken: respAuthToken.RefreshToken,
        }
        respBmxNamespaces, _, err := whisk.BmxService.GetBmxNamespaces(reqNamespaces)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxNamespaces(%s) error: %s\n", reqNamespaces, err)
            errMsg := wski18n.T("Unable to retrieve namespaces: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
                whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix namespaces: %#q\n", respBmxNamespaces)

        // 5. Prompt for which namespace to use
        var namespace whisk.BmxNamespaceResponse
        if !cmd.LocalFlags().Changed("namespace") {
            namespace = promptForNamespace(respBmxNamespaces.Namespaces)
            if len(namespace.Name) == 0 {
                whisk.Debug(whisk.DbgError, "No namespace for user `%s` was selected\n", bmxflags.username)
                errStr := wski18n.T("User '{{.name}}' must have at least one defined namespace", map[string]interface{}{"name": bmxflags.username})
                whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
                return whiskErr
            }
        } else {
            for _, ns := range respBmxNamespaces.Namespaces {
                if ns.Name == bmxflags.namespace {
                    namespace = ns
                }
            }
            if len(namespace.Name) == 0 {
                whisk.Debug(whisk.DbgError, "User `%s` is not entitled to access namespace `%s`\n", bmxflags.username, bmxflags.namespace)
                errStr := wski18n.T("Namespace '{{.name}}' is not in the list of entitled namespaces", map[string]interface{}{"name": bmxflags.namespace})
                whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
                return whiskErr
            }
        }
        whisk.Debug(whisk.DbgInfo, "Selected namespace: %#v\n", namespace)
        newAuthKey := namespace.UUID + ":" + namespace.Key

        // 6. Persist this token for use by subsequent 'wsk api' commands
        props, err := readProps(Properties.PropsFile)
        if err != nil {
            whisk.Debug(whisk.DbgError, "readProps(%s) failed: %s\n", Properties.PropsFile, err)
            errStr := wski18n.T("Unable to save the Bluemix login access token: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }
        props["APIGW_ACCESS_TOKEN"] = respAuthToken.AccessToken
        whisk.Debug(whisk.DbgInfo, "Replacing auth key %s with %s\n", props["AUTH"], newAuthKey)
        props["AUTH"] = newAuthKey
        err = writeProps(Properties.PropsFile, props)
        if err != nil {
            whisk.Debug(whisk.DbgError, "writeProps(%s, %#v) failed: %s\n", Properties.PropsFile, props, err)
            errStr := fmt.Sprintf(
                wski18n.T("Unable to save the Bluemix login access token: {{.err}}",
                    map[string]interface{}{"err": err}))
            whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }

        fmt.Fprintf(color.Output,
            wski18n.T("{{.ok}} User '{{.user}}' logged into Bluemix",
                map[string]interface{}{
                    "ok": color.GreenString("ok:"),
                    "user": bmxflags.username,
                }))
        return nil
    },
}

/*
 * Configure a HTTP client using the OpenWhisk properties (i.e. host, auth)
 */
func setupOpenWhiskClientConfig(cmd *cobra.Command, args []string) (error){
    // Configure a HTTP to access https://openwhisk.ng.bluemix.net based endpoints
    baseURL, err := getURLBase(Properties.APIHost, "")  // *url.URL is in form  https://openwhisk.ng.bluemix.net
    if err != nil {
        whisk.Debug(whisk.DbgError, "getURLBase(%s) error: %s\n", Properties.APIHost, err)
        errMsg := wski18n.T("Internal error. OpenWhisk API {{.api}} is invalid: {{.err}}",
            map[string]interface{}{"api": Properties.APIHost, "err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return whiskErr
    }

    clientConfig := &whisk.Config{
        BaseURL:    baseURL,
        Insecure:   flags.global.insecure,
        AuthToken:  Properties.Auth,
    }
    // Setup client
    owClient, err := whisk.NewClient(http.DefaultClient, clientConfig)
    if err != nil {
        whisk.Debug(whisk.DbgError, "whisk.NewClient(%#v, %#v) error: %s\n", http.DefaultClient, clientConfig, err)
        errMsg := wski18n.T("Unable to initialize server connection: {{.err}}", map[string]interface{}{"err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return whiskErr
    }
    whisk.BmxService.OwClient = owClient

    return nil
}

/*
 * Configure a HTTP client with the specified host
 */
func setupBmxClientConfig(bmxHost string) (*whisk.Client, error){
    baseURL, err := makeURL(bmxHost)  // *url.URL is in form  https://host.domain
    if err != nil {
        whisk.Debug(whisk.DbgError, "makeURL(%s) error: %s\n", bmxHost, err)
        errMsg := wski18n.T("Internal error. Bluemix API {{.api}} is invalid: {{.err}}",
            map[string]interface{}{"api": bmxHost, "err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return nil, whiskErr
    }

    clientConfig := &whisk.Config{
        BaseURL:    baseURL,
        Insecure:   flags.global.insecure,
        AuthToken:  "cf:",
    }

    // Setup client that accesses Bluemix API URL
    bmxClient, err := whisk.NewClient(http.DefaultClient, clientConfig)
    if err != nil {
        whisk.Debug(whisk.DbgError, "whisk.NewClient(%#v, %#v) error: %s\n", http.DefaultClient, clientConfig, err)
        errMsg := wski18n.T("Unable to initialize Bluemix server connection: {{.err}}", map[string]interface{}{"err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return nil, whiskErr
    }

    whisk.BmxService.BmxClient = bmxClient

    return bmxClient, nil
}

func makeURL(host string) (*url.URL, error)  {
    if len(host) == 0 {
        errMsg := wski18n.T("An API host must be provided.")
        whiskErr := whisk.MakeWskError(errors.New(errMsg), whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return nil, whiskErr
    }

    url, err := url.Parse(host)
    if len(url.Scheme) == 0 || len(url.Host) == 0 {
        urlBase := fmt.Sprintf("https://%s", host)
        url, err = url.Parse(urlBase)
    }

    return url, err
}

const maxSelections = 50
func promptForNamespace(namespaces []whisk.BmxNamespaceResponse) (whisk.BmxNamespaceResponse) {
    index := 0
    var name string
    var err error

    if len(namespaces) == 0 {
        whisk.Debug(whisk.DbgWarn, "promptForNamespace: Empty namespace list")
        return whisk.BmxNamespaceResponse{}
    }

    for (index < 1 || index > len(namespaces)) {
        fmt.Println(wski18n.T("Select a namespace:"))
        if len(namespaces) < maxSelections {
            for i, namespace := range namespaces {
                fmt.Printf("%d. %s\n", i+1, namespace.Name)
            }
        } else {
            fmt.Println(wski18n.T("There are too many namespaces to display, please type in the namespace name."))
        }

        fmt.Printf("namespace>")
        _, err = fmt.Scanln(&name)

        index, err = strconv.Atoi(name)
        if err != nil {
            // Not a number, treat the value as a manually entered namespace name.
            // If the manually typed namespace does not exist in the list, re-prompt
            for _, ns := range namespaces {
                if ns.Name == name {
                    return ns
                }
            }
        }
    }

    return namespaces[index-1]
}

func init() {
    bmxLoginCmd.Flags().StringVar(&bmxflags.username, "user", "", wski18n.T("Bluemix user `NAME`"))
    bmxLoginCmd.Flags().StringVar(&bmxflags.password, "password", "", wski18n.T("Bluemix user `PASSWORD`"))
    bmxLoginCmd.Flags().StringVar(&bmxflags.namespace, "namespace", "", wski18n.T("OpenWhisk `NAMESPACE`"))

    bmxCmd.AddCommand(
        bmxLoginCmd,
    )

    WskCmd.AddCommand(bmxCmd)
}

func generateBluemixApiHostAccessError(err error) (error) {
    errMsg := wski18n.T("Unable to access Bluemix API host: {{.err}}", map[string]interface{}{"err": err})
    return whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
        whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
}

func generateBluemixAuthEndpointAccessError(err error) (error) {
    errMsg := wski18n.T("Unable to access Bluemix authorization endpoint: {{.err}}", map[string]interface{}{"err": err})
    return whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
        whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
}
