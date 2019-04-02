/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using DotNetCoreCas.Validation.TicketValidator;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace DotNetCoreCas
{
    /// <summary>
    /// Default values in CAS Middleware
    /// </summary>
    public static class CASDefaults
    {
        /// <summary>
        /// Authentication Scheme for CAS
        /// </summary>
        public const string AuthenticationScheme = "CAS";
    }

    /// <summary>
    /// Names for the ticket validator to specify the type of server it is using.
    /// </summary>
    public enum TicketValidatorNames
    {
        SelectATicketValidatorName, Cas10, Cas20, Saml11
    }

    public class CasOptions : ICasOptions
    {
        #region Fields

        // Required Properties
        public const string CAS_SERVER_LOGIN_URL = "casServerLoginUrl";
        public const string CAS_SERVER_URL_PREFIX = "casServerUrlPrefix";
        public const string TICKET_VALIDATOR_NAME = "ticketValidatorName";

        // One of these Properties must be set. If both are set, service takes
        // precedence.
        public const string SERVER_NAME = "serverName";
        public const string SERVICE = "service";

        // Optional Properties
        public const string RENEW = "renew";
        public const string GATEWAY = "gateway";
        public const string GATEWAY_STATUS_COOKIE_NAME = "gatewayStatusCookieName";
        public const string ARTIFACT_PARAMETER_NAME = "artifactParameterName";
        public const string SERVICE_PARAMETER_NAME = "serviceParameterName";
        public const string REQUIRE_CAS_FOR_MISSING_CONTENT_TYPES_PARAMETER_NAME = "requireCasForMissingContentTypes";
        public const string REQUIRE_CAS_FOR_CONTENT_TYPES_PARAMETER_NAME = "requireCasForContentTypes";
        public const string BYPASS_CAS_FOR_HANDLERS_PARAMETER_NAME = "bypassCasForHandlers";
        public const string AUTHENTICATION_TYPE = "authenticationType";

        // NETC-20 - Not sure whether these attributes are relevant.
        // public const string ARTIFACT_PARAMETER_NAME_VALIDATION = "artifactParameterNameValidation";
        // public const string SERVICE_PARAMETER_NAME_VALIDATION = "serviceParameterNameValidation";

        public const string REDIRECT_AFTER_VALIDATION = "redirectAfterValidation";
        public const string ENCODE_SERVICE_URL = "encodeServiceUrl";
        public const string SECURE_URI_REGEX_STRING = "secureUriRegex";
        public const string SECURE_URI_EXCEPTION_REGEX_STRING = "secureUriExceptionRegex";
        public const string USE_SESSION = "useSession";
        public const string TICKET_TIME_TOLERANCE = "ticketTimeTolerance";
        public const string SINGLE_SIGN_OUT = "singleSignOut";
        public const string SERVICE_TICKET_MANAGER = "serviceTicketManager";
        public const string PROXY_TICKET_MANAGER = "proxyTicketManager";
        public const string NOT_AUTHORIZED_URL = "notAuthorizedUrl";
        public const string COOKIES_REQUIRED_URL = "cookiesRequiredUrl";
        public const string GATEWAY_PARAMETER_NAME = "gatewayParameterName";
        public const string PROXY_CALLBACK_PARAMETER_NAME = "proxyCallbackParameterName";
        public const string PROXY_CALLBACK_URL = "proxyCallbackUrl";

        // Names for the supported ticket validators
        public const string CAS10_TICKET_VALIDATOR_NAME = "Cas10";
        public const string CAS20_TICKET_VALIDATOR_NAME = "Cas20";
        public const string SAML11_TICKET_VALIDATOR_NAME = "Saml11";

        // Names for the supported Service Ticket state provider
        public const string CACHE_SERVICE_TICKET_MANAGER = "CacheServiceTicketManager";

        // Names for the supported Cache Ticket state provider
        public const string CACHE_PROXY_TICKET_MANAGER = "CacheProxyTicketManager";

        #endregion

        #region Properties

        /// <summary>
        /// Defines the exact CAS server login URL.
        /// e.g. https://cas.princeton.edu/cas/login
        /// </summary>
        [Required]
        public string CasServerLoginUrl { get; set; }

        /// <summary>
        /// Defines the prefix for the CAS server. Should be everything up to the URL endpoint,
        /// including the /.
        /// e.g. http://cas.princeton.edu/
        /// </summary>
        [Required]
        public string CasServerUrlPrefix { get; set; }

        /// <summary>
        /// The ticket validator to use to validate tickets returned by the CAS server.
        /// <remarks>
        /// Currently supported values: Cas10 / Cas20 / Saml11 or any fully qualified type which extends AbstractCasProtocolTicketValidator
        /// </remarks>
        /// </summary>
        [Required]
        public TicketValidatorNames TicketValidatorName { get; set; }

        /// <summary>
        /// Tolerance milliseconds for checking the current time against the SAML Assertion
        /// valid times.
        /// </summary>
        public long TicketTimeTolerance { get; set; } = 3000;

        /// <summary>
        /// The Service URL to send to the CAS server.
        /// e.g. https://app.princeton.edu/example/
        /// </summary>
        public string Service { get; set; }

        /// <summary>
        /// The server name of the server hosting the client application.  Service URL
        /// will be dynamically constructed using this value if Service is not specified.
        /// e.g. https://app.princeton.edu/
        /// </summary>
        [Required]
        public string ServerName { get; set; }

        /// <summary>
        /// Specifies whether renew=true should be sent to URL's directed to the
        /// CAS server.
        /// </summary>
        public bool Renew { get; set; } = false;

        /// <summary>
        /// Specifies whether or not to redirect to the CAS server logon for a gateway request.
        /// </summary>
        public bool Gateway { get; set; } = false;

        /// <summary>
        /// The name of the cookie used to store the Gateway status (NotAttempted, 
        /// Success, Failed).  This cookie is used to prevent the client from 
        /// attempting to gateway authenticate every request.
        /// </summary>
        public string GatewayStatusCookieName { get; set; } = "cas_gateway_status";

        /// <summary>
        /// Specifies the name of the request parameter whose value is the artifact (e.g. "ticket").
        /// </summary>
        public string ArtifactParameterName { get; set; } = "ticket";

        /// <summary>
        /// Specifies the name of the request parameter whose value is the service (e.g. "service")
        /// </summary>
        public string ServiceParameterName { get; set; } = "service";

        /// <summary>
        /// Specifies whether to require CAS for requests that have null/empty content-types
        /// </summary>
        public bool RequireCasForMissingContentTypes { get; set; } = true;

        /// <summary>
        /// Content-types for which CAS authentication will be required
        /// </summary>
        public string[] RequireCasForContentTypes { get; set; } = new[] { "text/plain", "text/html" };

        /// <summary>
        /// Handlers for which CAS authentication will be bypassed.
        /// </summary>
        public string[] BypassCasForHandlers { get; set; } = new[] { "trace.axd", "webresource.axd" };

        // public const string REQUIRE_CAS_FOR_CONTENT_TYPES_PARAMETER_NAME = "requireCasForContentTypes";
        // public const string BYPASS_CAS_FOR_HANDLERS_PARAMETER_NAME = "bypassCasForHandlers";

        /// <summary>
        /// Whether to redirect to the same URL after ticket validation, but without the ticket
        /// in the parameter.
        /// </summary>
        public bool RedirectAfterValidation { get; set; } = false;

        /// <summary>
        /// Whether to encode the session ID into the Service URL.
        /// </summary>
        public bool EncodeServiceUrl { get; set; } = false;

        /// <summary>
        /// Specifies whether single sign out functionality should be enabled.
        /// </summary>
        public bool SingleSignOut { get; set; } = true;

        /// <summary>
        /// The service ticket manager to use to store tickets returned by the 
        /// CAS server for validation, revocation, and single sign out support.
        /// <remarks>
        /// Currently supported values: A fully qualified type name supporting IServiceTicketManager or the short name of a type in DotNetCasClient.State
        /// </remarks>
        /// </summary>
        public string ServiceTicketManager { get; set; }

        /// <summary>
        /// The proxy ticket manager to use to store and resolve 
        /// ProxyGrantingTicket IOUs to ProxyGrantingTickets
        /// <remarks>
        /// Currently supported values: A fully qualified type name supporting IProxyTicketManager or the short name of a type in DotNetCasClient.State
        /// </remarks>
        /// </summary>
        public State.IProxyTicketManager ProxyTicketManager { get; set; }

        /// <summary>
        /// URL to redirect to when the request has a validated and verified 
        /// CAS Authentication Ticket, but the identity associated with that 
        /// ticket is not authorized to access the requested resource.  If this 
        /// option is omitted, the request will be redirected to the CAS server
        /// for alternate credentials (with the 'renew' argument set). 
        /// </summary>
        public string NotAuthorizedUrl { get; set; }

        /// <summary>
        /// The URL to redirect to when the client is not accepting session 
        /// cookies.  This condition is detected only when gateway is enabled.  
        /// This will lock the users onto a specific page.  Otherwise, every 
        /// request will cause a silent round-trip to the CAS server, adding 
        /// a parameter to the URL.
        /// </summary>
        public string CookiesRequiredUrl { get; set; } = null;

        /// <summary>
        /// The URL parameter to append to outbound CAS request's ServiceName 
        /// when initiating an automatic CAS Gateway request.  This parameter 
        /// plays a role in detecting whether or not the client has cookies 
        /// enabled.  The default value is 'gatewayResponse' and only needs to 
        /// be explicitly defined if that URL parameter has a meaning elsewhere
        /// in your application.  If you choose not define the CookiesRequiredUrl,
        /// you can detect that session cookies are not enabled in your application
        /// by testing for this parameter in the Request.QueryString having the 
        /// value 'true'.
        /// </summary>
        public string GatewayParameterName { get; set; } = "gatewayResponse";

        /// <summary>
        /// The URL parameter to append to outbound CAS proxy request's pgtUrl
        /// when initiating an proxy ticket service validation.  This is used
        /// to determine whether the request is originating from the CAS server
        /// and contains a pgtIou.
        /// </summary>
        public string ProxyCallbackParameterName { get; set; } = "proxyResponse";

        /// <summary>
        /// Defines the exact proxy call back url
        /// </summary>
        public string ProxyCallbackUrl { get; set; }
        /// <summary>
        /// Sets the AuthenticationType for IIdentity
        /// </summary>
        public string AuthenticationType { get; set; } = "Apereo CAS";

        private ITicketValidator ticketValidator;

        public Validation.TicketValidator.ITicketValidator TicketValidator
        {
            get
            {
                if (ticketValidator == null)
                {
                    if (TicketValidatorNames.Cas10 == TicketValidatorName)
                        ticketValidator = new Cas10TicketValidator();
                    else if (TicketValidatorNames.Cas20 == TicketValidatorName)
                        ticketValidator = new Cas20ServiceTicketValidator();
                    else if (TicketValidatorNames.Saml11 == TicketValidatorName)
                        ticketValidator = new Saml11TicketValidator();
                }
                return ticketValidator;
            }
        }

        public string CasProxyCallbackUrl { get; internal set; }

        /// <summary>
        /// This changes all references to localhost in the url to this current value.
        /// </summary>
        public string LocalHost { get; set; } = "localhost";

        public bool IsCaseSensitive { get; set; } = false;

        #endregion

        public void Validate()
        {
            if (TicketValidatorNames.Cas10 != TicketValidatorName && TicketValidatorNames.Cas20 != TicketValidatorName && TicketValidatorNames.Saml11 != TicketValidatorName)
            {
                throw new System.Exception("This is not a valid CAS options set.", new System.Exception("Incorrect TicketValidatorName"));
            }

            if ((string.IsNullOrWhiteSpace(this.ServerName) && string.IsNullOrWhiteSpace(this.Service))
                || string.IsNullOrWhiteSpace(this.CasServerLoginUrl)
                || string.IsNullOrWhiteSpace(this.CasServerUrlPrefix))
            {
                throw new System.Exception("This is not a valid CAS options set");
            }
        }
    }
}