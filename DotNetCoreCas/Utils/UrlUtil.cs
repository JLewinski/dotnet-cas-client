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

using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Specialized;
using System.Text;
using System.Web;

namespace DotNetCoreCas.Utils
{
    /// <summary>
    /// An internal class used to generate and modify URLs
    /// as needed for redirection and external communication.
    /// </summary>
    /// <remarks>
    /// See https://wiki.jasig.org/display/CASC/UrlUtil+Methods for additional
    /// information including sample output of each method.
    /// </remarks>
    /// <author>Scott Holodak</author>
    public sealed class UrlUtil
    {
        /// <summary>
        /// Constructs the URL to use for redirection to the CAS server for login
        /// </summary>
        /// <remarks>
        /// The server name is not parsed from the request for security reasons, which
        /// is why the service and server name configuration parameters exist.
        /// </remarks>
        /// <returns>The redirection URL to use</returns>
        public static string ConstructLoginRedirectUrl(HttpContext context, ICasOptions options)
        {
            if (options.Gateway && options.Renew)
            {
                throw new ArgumentException("Gateway and Renew parameters are mutually exclusive and cannot both be True");
            }

            EnhancedUriBuilder ub = new EnhancedUriBuilder(options.CasServerLoginUrl);
            ub.QueryItems.Set(options.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(ConstructServiceUrl(context, options)));

            if (options.Renew)
            {
                ub.QueryItems.Add("renew", "true");
            }
            else if (options.Gateway)
            {
                ub.QueryItems.Add("gateway", "true");
            }

            string url = ub.Uri.AbsoluteUri;

            return url;
        }

        /// <summary>
        /// Constructs a service URL using configured values in the following order:
        /// 1.  if not empty, the value configured for Service is used
        /// - otherwise -
        /// 2.  the value configured for ServerName is used together with HttpRequest
        ///     data
        /// </summary>
        /// <remarks>
        /// The server name is not parsed from the request for security reasons, which
        /// is why the service and server name configuration parameters exist, per Apereo
        /// website.
        /// </remarks>
        /// <returns>the service URL to use, not encoded</returns>
        public static string ConstructServiceUrl(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            StringBuilder buffer = new StringBuilder();
            if (!(options.ServerName.StartsWith("https://") || options.ServerName.StartsWith("http://")))
            {
                buffer.Append(request.IsHttps ? "https://" : "http://");
            }
            buffer.Append(options.ServerName);

            buffer.Append(request.PathBase.HasValue ? request.PathBase.Value : string.Empty);

            EnhancedUriBuilder ub = new EnhancedUriBuilder(buffer.ToString());
            if (ub.Path.Length == 1)
            {
                ub.Path = request.Path;
            }
            else
            {
                ub.Path += request.Path;
            }
            
            ub.QueryItems.Add(HttpUtility.ParseQueryString(request.QueryString.Value));
            ub.QueryItems.Remove(options.TicketValidator.ServiceParameterName);
            ub.QueryItems.Remove(options.TicketValidator.ArtifactParameterName);

            if (options.Gateway)
            {
                ub.QueryItems.Set(options.GatewayParameterName, "true");
            }
            else
            {
                ub.QueryItems.Remove(options.GatewayParameterName);
            }
            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Constructs a URL used to check the validitiy of a service ticket, with or without a proxy 
        /// callback URL, and with or without requiring renewed credentials.
        /// </summary>
        /// <remarks>See CAS Protocol specification, section 2.5</remarks>
        /// <param name="serviceTicket">The service ticket to validate.</param>
        /// <param name="renew">
        /// Whether or not renewed credentials are required.  If True, ticket validation
        /// will fail for Single Sign On credentials.
        /// </param>
        /// <param name="gateway">
        /// whether or not to include gatewayResponse=true in the request (client specific).
        /// </param>
        /// <param name="customParameters">custom parameters to add to the validation URL</param>
        /// <returns>The service ticket validation URL to use</returns>
        public static string ConstructValidateUrl(HttpContext context, string serviceTicket, bool gateway, bool renew, NameValueCollection customParameters, ICasOptions options)
        {
            if (gateway && renew)
            {
                throw new ArgumentException("Gateway and Renew parameters are mutually exclusive and cannot both be True");
            }

            // CasAuthentication.Initialize();

            EnhancedUriBuilder ub = new EnhancedUriBuilder(EnhancedUriBuilder.Combine(options.CasServerUrlPrefix, options.TicketValidator.UrlSuffix));
            ub.QueryItems.Add(options.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(ConstructServiceUrl(context, options)));
            ub.QueryItems.Add(options.TicketValidator.ArtifactParameterName, HttpUtility.UrlEncode(serviceTicket));

            if (renew)
            {
                ub.QueryItems.Set("renew", "true");
            }

            if (customParameters != null)
            {
                for (int i = 0; i < customParameters.Count; i++)
                {
                    string key = customParameters.AllKeys[i];
                    string value = customParameters[i];

                    ub.QueryItems.Add(key, value);
                }
            }
            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Constructs a proxy callback URL containing a ProxyCallbackParameter 
        /// (proxyResponse by default).  This URL is sent to the CAS server during a proxy
        /// ticket request and is then connected to by the CAS server. If the 'CasProxyCallbackUrl' settings is specified,
        /// its value will be used to construct the proxy url. Otherwise, `ServerName` will be used.
        /// If the CAS server cannot successfully connect (generally due to SSL configuration issues), the
        /// CAS server will refuse to send a proxy ticket. 
        /// </summary>
        /// <returns>the proxy callback URL to use</returns>
        public static string ConstructProxyCallbackUrl(HttpContext context, bool gateway, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            EnhancedUriBuilder ub = null;
            if (options.CasProxyCallbackUrl != null && options.CasProxyCallbackUrl.Length > 0)
            {
                ub = new EnhancedUriBuilder(options.CasProxyCallbackUrl);
            }
            else
            {
                ub = new EnhancedUriBuilder(options.ServerName);
                ub.Path = request.Path.ToUriComponent();
            }

            if (request.QueryString.HasValue)
            {
                ub.QueryItems.Add(HttpUtility.ParseQueryString(request.QueryString.Value));
            }
            ub.QueryItems.Remove(options.TicketValidator.ArtifactParameterName);

            if (gateway)
            {
                ub.QueryItems.Set(options.GatewayParameterName, "true");
            }
            else
            {
                ub.QueryItems.Remove(options.GatewayParameterName);
            }
            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Constructs a proxy callback URL containing a ProxyCallbackParameter 
        /// (proxyResponse by default).  This URL is sent to the CAS server during a proxy
        /// ticket request and is then connected to by the CAS server.  If the CAS server
        /// cannot successfully connect (generally due to SSL configuration issues), the
        /// CAS server will refuse to send a proxy ticket. 
        /// </summary>
        /// <remarks>
        /// This is a .NET implementation specific method used to eliminate the need for 
        /// a special HTTP Handler.  Essentially, if the client detects an incoming request
        /// with the ProxyCallbackParameter in the URL (i.e., proxyResponse), that request 
        /// is treated specially and behaves as if it were handled by an HTTP Handler.  In 
        /// other words, this behavior may or may not short circuit the request event 
        /// processing and will not allow the underlying page to execute and transmit back to
        /// the client.  If your application does coincidentally make use of the key 
        /// 'proxyResponse' as a URL parameter, you will need to configure a custom 
        /// proxyCallbackParameter value which does not conflict with the URL parameters in
        /// your application.
        /// </remarks>
        /// <returns>the proxy callback URL to use</returns>
        public static string ConstructProxyCallbackUrl(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            EnhancedUriBuilder ub = new EnhancedUriBuilder(ConstructProxyCallbackUrl(context, false, options));
            ub.QueryItems.Set(options.ProxyCallbackParameterName, "true");

            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Constructs a proxy ticket request URL containing both a proxy granting 
        /// ticket and a URL Encoded targetServiceUrl.  The URL returned will generally only
        /// be executed by the CAS client as a part of a proxy redirection in 
        /// CasAuthentication.ProxyRedirect(...) or CasAuthentication.GetProxyTicketIdFor(...)
        /// but may also be used by applications which require low-level access to the proxy
        /// ticket request functionality.
        /// </summary>
        /// <param name="proxyGrantingTicketId">
        /// The proxy granting ticket used to authorize the request for a proxy ticket on the 
        /// CAS server
        /// </param>
        /// <param name="targetService">
        /// The target service URL to request a proxy ticket request URL for
        /// </param>
        /// <returns>The URL to use to request a proxy ticket for the targetService specified</returns>
        public static string ConstructProxyTicketRequestUrl(string proxyGrantingTicketId, string targetService, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            if (String.IsNullOrEmpty(proxyGrantingTicketId))
            {
                throw new ArgumentException("For proxy ticket requests, proxyGrantingTicketId cannot be null and must be specified.");
            }

            if (String.IsNullOrEmpty(targetService))
            {
                throw new ArgumentException("For proxy ticket requests, targetService cannot be null and must be specified.");
            }

            // TODO: Make "proxy" configurable.
            EnhancedUriBuilder ub = new EnhancedUriBuilder(EnhancedUriBuilder.Combine(options.CasServerUrlPrefix, "proxy"));
            ub.QueryItems.Add("pgt", proxyGrantingTicketId);
            ub.QueryItems.Add("targetService", HttpUtility.UrlEncode(targetService));

            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Attempts to request a proxy ticket for the targetService specified and
        /// returns a URL appropriate for redirection to the targetService containing
        /// a ticket.
        /// </summary>
        /// <param name="targetService">The target service for proxy authentication</param>
        /// <returns>The URL of the target service with a proxy ticket included</returns>
        public static string GetProxyRedirectUrl(HttpContext context, string targetService, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            // Todo: Is ResolveUrl(...) appropriate/necessary?  If the URL starts with ~, it shouldn't require proxy authentication
            string resolvedUrl = ResolveUrl(context, targetService);
            string proxyTicket = GetProxyTicketIdFor(resolvedUrl);

            EnhancedUriBuilder ub = new EnhancedUriBuilder(resolvedUrl);
            ub.QueryItems[options.TicketValidator.ArtifactParameterName] = proxyTicket;

            return ub.Uri.AbsoluteUri;
        }

        internal static string GetProxyTicketIdFor(string resolvedUrl)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Attempts to request a proxy ticket for the targetService specified and
        /// returns a URL appropriate for redirection to the targetService containing
        /// a ticket.
        /// </summary>
        /// <param name="targetService">The target service for proxy authentication</param>
        /// <param name="proxyTicketUrlParameter">
        /// The name of the ticket URL parameter expected by the target service (ticket by
        /// default)
        /// </param>
        /// <returns>The URL of the target service with a proxy ticket included</returns>
        // public static string GetProxyRedirectUrl(HttpContext context, string targetService, string proxyTicketUrlParameter, ICasOptions options)
        // {
        //     // CasAuthentication.Initialize();

        //     // Todo: Is ResolveUrl(...) appropriate/necessary?  If the URL starts with ~, it shouldn't require proxy authentication
        //     string resolvedUrl = ResolveUrl(context, targetService);
        //     string proxyTicket = CasAuthentication.GetProxyTicketIdFor(resolvedUrl);

        //     EnhancedUriBuilder ub = new EnhancedUriBuilder(resolvedUrl);
        //     ub.QueryItems[options.TicketValidator.ArtifactParameterName] = proxyTicket;

        //     return ub.Uri.AbsoluteUri;
        // }

        /// <summary>
        /// Constructs the URL to use for redirection to the CAS server for single
        /// signout.  The CAS server will invalidate the ticket granting ticket and
        /// redirect back to the current page.  The web application must then call
        /// ClearAuthCookie and revoke the ticket from the ServiceTicketManager to sign 
        /// the client out.
        /// </summary>
        /// <returns>the redirection URL to use, not encoded</returns>
        public static string ConstructSingleSignOutRedirectUrl(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            // TODO: Make "logout" configurable
            EnhancedUriBuilder ub = new EnhancedUriBuilder(EnhancedUriBuilder.Combine(options.CasServerUrlPrefix, "logout"));
            ub.QueryItems.Set(options.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(ConstructServiceUrl(context, options)));

            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Returns a copy of the URL supplied modified to remove CAS protocol-specific
        /// URL parameters.
        /// </summary>
        /// <param name="url">The URL to remove CAS artifacts from</param>
        /// <returns>The URL supplied without CAS artifacts</returns>
        public static string RemoveCasArtifactsFromUrl(string url, ICasOptions options)
        {
            CommonUtils.AssertNotNullOrEmpty(url, "url parameter can not be null or empty.");

            // CasAuthentication.Initialize();

            EnhancedUriBuilder ub = new EnhancedUriBuilder(url);
            ub.QueryItems.Remove(options.TicketValidator.ArtifactParameterName);
            ub.QueryItems.Remove(options.TicketValidator.ServiceParameterName);
            ub.QueryItems.Remove(options.GatewayParameterName);
            ub.QueryItems.Remove(options.ProxyCallbackParameterName);

            // ++ NETC-28
            Uri uriServerName;
            if (options.ServerName.StartsWith("http://", StringComparison.InvariantCultureIgnoreCase) ||
                options.ServerName.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase))
            {
                uriServerName = new Uri(options.ServerName);
            }
            else
            {
                // .NET URIs require scheme
                uriServerName = new Uri("https://" + options.ServerName);
            }

            ub.Scheme = uriServerName.Scheme;
            ub.Host = uriServerName.Host;
            ub.Port = uriServerName.Port;

            return ub.Uri.AbsoluteUri;
        }

        /// <summary>
        /// Resolves a relative ~/Url to a Url that is meaningful to the
        /// client.
        /// <remarks>
        /// Derived from: http://weblogs.asp.net/palermo4/archive/2004/06/18/getting-the-absolute-path-in-asp-net-part-2.aspx
        /// </remarks>        
        /// </summary>
        /// <author>J. Michael Palermo IV</author>
        /// <author>Scott Holodak</author>
        /// <param name="url">The Url to resolve</param>
        /// <returns>The fullly resolved Url</returns>
        internal static string ResolveUrl(HttpContext context, string url)
        {
            CommonUtils.AssertNotNullOrEmpty(url, "url parameter can not be null or empty.");
            if (url[0] != '~') return url;

            // CasAuthentication.Initialize();

            string applicationPath = context.Request.Path;
            if (url.Length == 1) return applicationPath;

            // assume url looks like ~somePage 
            int indexOfUrl = 1;

            // determine the middle character 
            string midPath = ((applicationPath ?? string.Empty).Length > 1) ? "/" : string.Empty;

            // if url looks like ~/ or ~\ change the indexOfUrl to 2 
            if (url[1] == '/' || url[1] == '\\') indexOfUrl = 2;

            return applicationPath + midPath + url.Substring(indexOfUrl);
        }
    }
}
