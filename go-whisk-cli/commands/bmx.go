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

    "github.com/apache/incubator-openwhisk-client-go/whisk"
    whisk_bluemix "github.com/IBM-Bluemix/bluemix-cli-openwhisk/go-whisk/whisk"
    "github.com/apache/incubator-oopenwhisk-cli/commands"
    "github.com/IBM-Bluemix/bluemix-cli-openwhisk/go-whisk-cli/wski18n"

    "github.com/fatih/color"
    "github.com/spf13/cobra"
    "github.com/mitchellh/go-homedir"

    "net/http"
    "net/url"
    "strconv"
    "encoding/json"
    "strings"
)

var bmxflags struct {
    username   string
    password   string
    namespace  string
    sso        bool
}

// Structs for parsing the Cloud Foundry config.json
type CloudFoundryConfigJson struct {
    AccessToken     string    `json:"AccessToken"`
    RefreshToken    string    `json:"RefreshToken"`
    Org             *CfOrg    `json:"OrganizationFields"`
    Space           *CfSpace  `json:"SpaceFields"`
}
type CfOrg struct {
    Name            string    `json:"Name"`
}
type CfSpace struct {
    Namespace       string    `json:"Name"`
    Guid            string    `json:"GUID"`
}

//////////////
// Commands //
//////////////

var bmxCmd = &cobra.Command{
    Use:   "bluemix",
    Short: wski18n.T("bluemix integration"),
}

var bmxLoginCmd = &cobra.Command{
    Use:           "login ( (--user BMX_USER_NAME --password BMX_USER_PASSWORD) | --sso ) [--namespace NAMESPACE]",
    Short:         wski18n.T("login to Bluemix"),
    SilenceUsage:  true,
    SilenceErrors: true,
    PreRunE:       setupOpenWhiskClientConfig,
    RunE: func(cmd *cobra.Command, args []string) error {

        // 0. Validate command arguments
        err := validateArgs(cmd, args)
        if err != nil {
            errMsg := wski18n.T("Invalid args: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
            return whiskErr
        }

        // 1. Query OpenWhisk for the Bluemix API endpoint
        reqBmxEndpoint := new(whisk_bluemix.BmxEndpointRequest)
        respBmxEndpoint, _, err := whisk_bluemix.BmxService.GetBmxApiHost(reqBmxEndpoint)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxApiHost(%#v, false) error: %s\n", reqBmxEndpoint, err)
            return generateBluemixApiHostAccessError(err)
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix API: %s\n", respBmxEndpoint.BmxApi)
        whisk_bluemix.BmxService.BmxClient, err = setupBmxClientConfig(respBmxEndpoint.BmxApi)
        if err != nil {
            whisk.Debug(whisk.DbgError, "setupBmxClientConfig(%s) error: %s\n", respBmxEndpoint.BmxApi, err)
            return generateBluemixApiHostAccessError(err)
        }

        // 2. Query the Bluemix API endpoint for the Bluemix UAA endpoint
        bmxApiUrl := fmt.Sprintf("https://%s/v2/info", respBmxEndpoint.BmxApi)
        respBmxInfo, _, err := whisk_bluemix.BmxService.GetBmxInfo(bmxApiUrl)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxInfo(%s) error: %s\n", bmxApiUrl, err)
            return generateBluemixAuthEndpointAccessError(err)
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix authorization endpoint: %s\n", respBmxInfo.AuthEndpoint)
        whisk_bluemix.BmxService.BmxClient, err = setupBmxClientConfig(respBmxInfo.AuthEndpoint)
        if err != nil {
            whisk.Debug(whisk.DbgError, "setupBmxClientConfig(%s) error: %s\n", respBmxEndpoint.BmxApi, err)
            return generateBluemixAuthEndpointAccessError(err)
        }

        // 3. Obtain the user's Bluemix access/bearer token
        //    If the --sso option was specified, obtain the token from the bluemix cli config.json;
        //    otherwise, query the Bluemix UAA endpoint for the access token
        var respAuthToken *whisk.AuthTokenResponse
        if (bmxflags.sso) {
            // Obtain needed config.json properties
            whisk.Debug(whisk.DbgInfo, "Obtaining access token from CF config.json\n")
            cfCfg, err := getCfConfig()
            if err != nil {
                whisk.Debug(whisk.DbgError, "getCfConfig error: %s\n", err)
                errMsg := wski18n.T("Unable to authenticate with Bluemix: {{.err}}", map[string]interface{}{"err": err})
                whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
                    whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
                return whiskErr
            }
            // Use these user tokens fpr the remainder of the login process
            respAuthToken = &whisk.AuthTokenResponse{}
            respAuthToken.AccessToken = cfCfg.AccessToken
            respAuthToken.RefreshToken = cfCfg.RefreshToken
        } else {
            whisk.Debug(whisk.DbgInfo, "Bluemix client baseURL: %s\n", whisk.BmxService.BmxClient.BaseURL)
            reqAuthToken := &whisk.AuthTokenRequest{
                UserName: bmxflags.username,
                UserPassword: bmxflags.password,
                GrantType: "password",
                ResponseType: "token",
            }
            respAuthToken, _, err = whisk.BmxService.GetBmxAuthToken(reqAuthToken)
            if err != nil {
                whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxAuthToken(%s) error: %s\n", respBmxInfo.AuthEndpoint, err)
                errMsg := wski18n.T("Unable to authenticate with Bluemix: {{.err}}", map[string]interface{}{"err": err})
                whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
                    whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
                return whiskErr
            }
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix access token: %#v\n", respAuthToken)

        // 4. Retrieve the namespaces associated with this login
        reqNamespaces := &whisk_bluemix.BmxNamespacesRequest{
            AccessToken: respAuthToken.AccessToken,
            RefreshToken: respAuthToken.RefreshToken,
        }
        respBmxNamespaces, _, err := whisk_bluemix.BmxService.GetBmxNamespaces(reqNamespaces)
        if err != nil {
            whisk.Debug(whisk.DbgError, "whisk.BmxService.GetBmxNamespaces(%s) error: %s\n", reqNamespaces, err)
            errMsg := wski18n.T("Unable to retrieve namespaces: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_NETWORK,
                whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }
        whisk.Debug(whisk.DbgInfo, "Bluemix namespaces: %#q\n", respBmxNamespaces)

        // 5. Prompt for which namespace to use
        var namespace whisk_bluemix.BmxNamespaceResponse
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
        props, err := commands.ReadProps(commands.Properties.PropsFile)
        if err != nil {
            whisk.Debug(whisk.DbgError, "readProps(%s) failed: %s\n", commands.Properties.PropsFile, err)
            errStr := wski18n.T("Unable to save the Bluemix login access token: {{.err}}", map[string]interface{}{"err": err})
            whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }
        props["APIGW_ACCESS_TOKEN"] = respAuthToken.AccessToken
        whisk.Debug(whisk.DbgInfo, "Replacing auth key %s with %s\n", props["AUTH"], newAuthKey)
        props["AUTH"] = newAuthKey
        err = commands.WriteProps(commands.Properties.PropsFile, props)
        if err != nil {
            whisk.Debug(whisk.DbgError, "writeProps(%s, %#v) failed: %s\n", commands.Properties.PropsFile, props, err)
            errStr := fmt.Sprintf(
                wski18n.T("Unable to save the Bluemix login access token: {{.err}}",
                    map[string]interface{}{"err": err}))
            whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
            return whiskErr
        }

        // If user name explicitly specified, use it in the exit message
        // If the --sso option was used, don't rely on the CLI user name; use the sso provide one
        var userName = bmxflags.username
        if bmxflags.sso {
            userName = respBmxNamespaces.Subject
        }
        fmt.Fprintln(color.Output,
            wski18n.T("{{.ok}} User '{{.user}}' logged into Bluemix",
                map[string]interface{}{
                    "ok": color.GreenString("ok:"),
                    "user": userName,
                }))

        return nil
    },
}

/*
 * Validate `wsk bluemix login` arguments
 */
func validateArgs(cmd *cobra.Command, args []string) (whiskError error) {
    whisk.Debug(whisk.DbgInfo, "bmxflags: %+v\n", bmxflags)

    // When --sso is NOT specified, a user/password must be provided
    if !cmd.LocalFlags().Changed("sso") && !(cmd.LocalFlags().Changed("user") && cmd.LocalFlags().Changed("password")) {
        errMsg := wski18n.T("User name and/or password were not specified")
        whiskErr := whisk.MakeWskError(errors.New(errMsg), whisk.EXITCODE_ERR_NETWORK, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
        return whiskErr
    }

    // When --sso IS provided, a user or password must NOT be provided
    if cmd.LocalFlags().Changed("sso") && (cmd.LocalFlags().Changed("user") || cmd.LocalFlags().Changed("password")) {
        errMsg := wski18n.T("When the --sso option is used, do not specify a user name or password")
        whiskErr := whisk.MakeWskError(errors.New(errMsg), whisk.EXITCODE_ERR_NETWORK, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
        return whiskErr
    }

    return nil
}

/*
 * Configure a HTTP client using the OpenWhisk properties (i.e. host, auth)
 */
func setupOpenWhiskClientConfig(cmd *cobra.Command, args []string) (error){
    // Configure a HTTP to access https://openwhisk.ng.bluemix.net based endpoints
    baseURL, err := commands.GetURLBase(commands.Properties.APIHost, "")  // *url.URL is in form  https://openwhisk.ng.bluemix.net
    if err != nil {
        whisk.Debug(whisk.DbgError, "GetURLBase(%s) error: %s\n", commands.Properties.APIHost, err)
        errMsg := wski18n.T("Internal error. OpenWhisk API {{.api}} is invalid: {{.err}}",
            map[string]interface{}{"api": commands.Properties.APIHost, "err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return whiskErr
    }

    clientConfig := &whisk.Config{
        BaseURL:    baseURL,
        Insecure:   commands.Flags.Global.Insecure,
        AuthToken:  commands.Properties.Auth,
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
    whisk_bluemix.BmxService.OwClient = owClient

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
        Insecure:   commands.Flags.Global.Insecure,
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

    whisk_bluemix.BmxService.BmxClient = bmxClient

    return bmxClient, nil
}

// Read the user's bluemix or cf generated config.json
// If present, the file is located under the user's HOMEDIR
func getCfConfig() (*CloudFoundryConfigJson, error) {
    const bmxcfPath = "~/.bluemix/.cf/config.json"

    // Generate a path to the config.json file
    bmxcfConfigFullPath, err := homedir.Expand(bmxcfPath)
    if err != nil {
        whisk.Debug(whisk.DbgError, "homedir.Expand(%s) failed: %s\n", Properties.PropsFile, err)
        errStr := fmt.Sprintf(
            wski18n.T("Unable to locate config file '{{.filename}}': {{.err}}",
                map[string]interface{}{"filename": bmxcfPath, "err": err}))
        whiskErr := whisk.MakeWskError(errors.New(errStr), whisk.EXITCODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
        return nil, whiskErr
    }

    cfConfig, err:= readFile(bmxcfConfigFullPath)
    if ( err != nil ) {
        whisk.Debug(whisk.DbgError, "readFile(%s) error: %s\n", bmxcfConfigFullPath, err)
        errMsg := wski18n.T("Error reading config file '{{.name}}': {{.err}}",
            map[string]interface{}{"name": bmxcfConfigFullPath, "err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return nil, whiskErr
    }

    // Parse the JSON into a cf config object
    cfConfigObj := new(CloudFoundryConfigJson)
    err = json.Unmarshal([]byte(cfConfig), cfConfigObj)
    if ( err != nil ) {
        whisk.Debug(whisk.DbgError, "JSON parse of `%s' error: %s\n", bmxcfConfigFullPath, err)
        errMsg := wski18n.T("Error parsing config file '{{.name}}': {{.err}}",
            map[string]interface{}{"name": bmxcfConfigFullPath, "err": err})
        whiskErr := whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXITCODE_ERR_GENERAL,
            whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
        return nil, whiskErr
    }

    // Remove any existing "bearer " prefix from the access token
    strArr := strings.Split(cfConfigObj.AccessToken, " ")
    if len(strArr) > 1 {
        cfConfigObj.AccessToken = strArr[1]
    }

    return cfConfigObj, nil
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
func promptForNamespace(namespaces []whisk_bluemix.BmxNamespaceResponse) (whisk_bluemix.BmxNamespaceResponse) {
    index := 0
    var name string
    var err error

    if len(namespaces) == 0 {
        whisk.Debug(whisk.DbgWarn, "promptForNamespace: Empty namespace list")
        return whisk_bluemix.BmxNamespaceResponse{}
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
    bmxLoginCmd.Flags().BoolVar(&bmxflags.sso, "sso", false, wski18n.T("Use 'bluemix login --sso' access token"))

    bmxCmd.AddCommand(
        bmxLoginCmd,
    )

    commands.WskCmd.AddCommand(bmxCmd)
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

func BMExecute() error {
    return commands.Execute()
}
