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
using System.Globalization;
using System.Web;

namespace DotNetCoreCas.Utils
{
    /// <summary>
    /// A utility class for evaluating the type of request 
    /// </summary>
    /// <author>Scott Holodak</author>
    public static class RequestEvaluator
    {
        /// <summary>
        /// Determines whether the request has a CAS ticket in the URL
        /// </summary>
        /// <returns>True if the request URL contains a CAS ticket, otherwise False</returns>
        public static bool GetRequestHasCasTicket(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;

            var request = HttpUtility.ParseQueryString(context.Request.QueryString.Value);

            bool result =
            (
                request[options.TicketValidator.ArtifactParameterName] != null &&
                !String.IsNullOrEmpty(request[options.TicketValidator.ArtifactParameterName])
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request is a return request from the 
        /// CAS server containing a CAS ticket
        /// </summary>
        /// <returns>True if the request URL contains a CAS ticket, otherwise False</returns>
        internal static bool GetRequestIsCasAuthenticationResponse(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            int artifactIndex = request.Path.ToUriComponent().IndexOf(options.TicketValidator.ArtifactParameterName);

            bool result =
            (
                GetRequestHasCasTicket(context, options) &&
                artifactIndex > 0 &&
                (
                    request.Path.ToUriComponent()[artifactIndex - 1] == '?' ||
                    request.Path.ToUriComponent()[artifactIndex - 1] == '&'
                )
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request contains the GatewayParameterName defined in 
        /// web.config or the default value 'gatewayResponse'
        /// </summary>
        /// <returns>True if the request contains the GatewayParameterName, otherwise False</returns>
        internal static bool GetRequestHasGatewayParameter(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            if (!request.QueryString.HasValue)
            {
                return false;
            }
            var quesryString = HttpUtility.ParseQueryString(request.QueryString.Value);

            bool requestContainsGatewayParameter = !String.IsNullOrEmpty(quesryString[options.GatewayParameterName]);
            bool gatewayParameterValueIsTrue = (quesryString[options.GatewayParameterName] == "true");

            bool result =
            (
               requestContainsGatewayParameter &&
               gatewayParameterValueIsTrue
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request is an inbound proxy callback verifications 
        /// from the CAS server
        /// </summary>
        /// <returns>True if the request is a proxy callback verificiation, otherwise False</returns>
        internal static bool GetRequestIsProxyResponse(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            if (!request.QueryString.HasValue)
            {
                return false;
            }
            var quesryString = HttpUtility.ParseQueryString(request.QueryString.Value);

            bool requestContainsProxyCallbackParameter = !String.IsNullOrEmpty(quesryString[options.ProxyCallbackParameterName]);
            bool proxyCallbackParameterValueIsTrue = (quesryString[options.ProxyCallbackParameterName] == "true");

            bool result =
            (
               requestContainsProxyCallbackParameter &&
               proxyCallbackParameterValueIsTrue
            );

            return result;
        }

        internal static GatewayStatus GetGatewayStatus()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Determines whether the current request requires a Gateway authentication redirect
        /// </summary>
        /// <returns>True if the request requires Gateway authentication, otherwise False</returns>
        internal static bool GetRequestRequiresGateway(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            GatewayStatus status = GetGatewayStatus();

            bool gatewayEnabled = options.Gateway;
            bool gatewayWasNotAttempted = (status == GatewayStatus.NotAttempted);
            bool requestDoesNotHaveGatewayParameter = !GetRequestHasGatewayParameter(context, options);
            bool cookiesRequiredUrlIsDefined = !string.IsNullOrEmpty(options.CookiesRequiredUrl);
            bool requestIsNotCookiesRequiredUrl = !GetRequestIsCookiesRequiredUrl(context, options);
            bool notAuthorizedUrlIsDefined = !String.IsNullOrEmpty(options.NotAuthorizedUrl);
            bool requestIsNotAuthorizedUrl = notAuthorizedUrlIsDefined && request.Path.Value.StartsWith(UrlUtil.ResolveUrl(context, options.NotAuthorizedUrl), true, CultureInfo.InvariantCulture);

            bool result =
            (
                gatewayEnabled &&
                gatewayWasNotAttempted &&
                requestDoesNotHaveGatewayParameter &&
                cookiesRequiredUrlIsDefined &&
                requestIsNotCookiesRequiredUrl &&
                !requestIsNotAuthorizedUrl
            );

            return result;
        }

        /// <summary>
        /// Determines whether the user's browser refuses to accept session cookies
        /// </summary>
        /// <returns>True if the browser does not allow session cookies, otherwise False</returns>
        internal static bool GetUserDoesNotAllowSessionCookies(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            // If the request has a gateway parameter but the cookie does not
            // reflect the fact that gateway was attempted, then cookies must
            // be disabled.
            GatewayStatus status = GetGatewayStatus();

            bool gatewayEnabled = options.Gateway;
            bool gatewayWasNotAttempted = (status == GatewayStatus.NotAttempted);
            bool requestHasGatewayParameter = GetRequestHasGatewayParameter(context, options);
            bool cookiesRequiredUrlIsDefined = !string.IsNullOrEmpty(options.CookiesRequiredUrl);
            bool requestIsNotCookiesRequiredUrl = cookiesRequiredUrlIsDefined && !GetRequestIsCookiesRequiredUrl(context, options);

            bool result =
            (
                gatewayEnabled &&
                gatewayWasNotAttempted &&
                requestHasGatewayParameter &&
                requestIsNotCookiesRequiredUrl
            );

            return result;
        }

        /// <summary>
        /// Determines whether the current request is unauthorized
        /// </summary>
        /// <returns>True if the request is unauthorized, otherwise False</returns>
        internal static bool GetRequestIsUnauthorized(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            HttpResponse response = context.Response;

            bool responseIsBeingRedirected = (response.StatusCode == 302);
            bool userIsAuthenticated = GetUserIsAuthenticated(context);
            bool responseIsCasLoginRedirect = GetResponseIsCasLoginRedirect(context, options);

            bool result =
            (
               responseIsBeingRedirected &&
               userIsAuthenticated &&
               responseIsCasLoginRedirect
            );

            return result;
        }

        /// <summary>
        /// Determines whether the current request is unauthenticated
        /// </summary>
        /// <returns>True if the request is unauthenticated, otherwise False</returns>
        internal static bool GetRequestIsUnAuthenticated(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            bool userIsNotAuthenticated = !GetUserIsAuthenticated(context);
            bool responseIsCasLoginRedirect = GetResponseIsCasLoginRedirect(context, options);

            bool result =
            (
                userIsNotAuthenticated &&
                responseIsCasLoginRedirect
            );

            return result;
        }

        /// <summary>
        /// Determines whether the current request will be redirected to the 
        /// CAS login page
        /// </summary>
        /// <returns>True if the request will be redirected, otherwise False.</returns>
        private static bool GetResponseIsCasLoginRedirect(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpResponse response = context.Response;

            bool requestDoesNotHaveCasTicket = !GetRequestHasCasTicket(context, options);
            bool responseIsBeingRedirected = (response.StatusCode == 302);
            bool responseRedirectsToFormsLoginUrl = true;// !String.IsNullOrEmpty(response.RedirectLocation) && response.RedirectLocation.StartsWith(CasAuthentication.FormsLoginUrl);

            bool result =
            (
               requestDoesNotHaveCasTicket &&
               responseIsBeingRedirected &&
               responseRedirectsToFormsLoginUrl
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request is a CAS Single Sign Out request
        /// </summary>
        /// <returns>True if the request is a CAS Single Sign Out request, otherwise False</returns>
        internal static bool GetRequestIsCasSingleSignOut(HttpContext context)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            bool requestIsFormPost = (request.Method == "POST");

            //bool haveLogoutRequest = !string.IsNullOrEmpty(request.Params["logoutRequest"]);
            bool haveLogoutRequest = !string.IsNullOrEmpty(HttpUtility.ParseQueryString(request.QueryString.Value)["logoutRequest"]);

            bool result =
            (
                requestIsFormPost &&
                haveLogoutRequest
            );

            return result;
        }

        /// <summary>
        /// Determines whether the User associated with the request has been 
        /// defined and is authenticated.
        /// </summary>
        /// <returns>True if the request has an authenticated User, otherwise False</returns>
        private static bool GetUserIsAuthenticated(HttpContext context)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;

            bool result =
            (
               context.User != null &&
               context.User.Identity.IsAuthenticated
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request is for the CookiesRequiredUrl defined in web.config
        /// </summary>
        /// <returns>True if the request is to the CookiesRequiredUrl, otherwise False</returns>
        private static bool GetRequestIsCookiesRequiredUrl(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;

            bool cookiesRequiredUrlIsDefined = !String.IsNullOrEmpty(options.CookiesRequiredUrl);
            bool requestIsCookiesRequiredUrl = cookiesRequiredUrlIsDefined && request.Path.ToUriComponent().StartsWith(UrlUtil.ResolveUrl(context, options.CookiesRequiredUrl), true, CultureInfo.InvariantCulture);

            bool result =
            (
                requestIsCookiesRequiredUrl
            );

            return result;
        }

        /// <summary>
        /// Determines whether the request is appropriate for CAS authentication.
        /// Generally, this is true for most requests except those for images,
        /// style sheets, javascript files and anything generated by the built-in
        /// ASP.NET handlers (i.e., web resources, trace handler).
        /// </summary>
        /// <returns>True if the request is appropriate for CAS authentication, otherwise False</returns>
        public static bool GetRequestIsAppropriateForCasAuthentication(HttpContext context, ICasOptions options)
        {
            // CasAuthentication.Initialize();

            //HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;
            HttpResponse response = context.Response;
            var uri = request.rawUrl(options);

            string contentType = response.ContentType;
            string fileName = uri.Segments[uri.Segments.Length - 1];

            bool contentTypeIsEligible = false;
            bool fileNameIsEligible = true;

            if (string.IsNullOrEmpty(contentType) && options.RequireCasForMissingContentTypes)
            {
                contentTypeIsEligible = true;
            }

            if (!contentTypeIsEligible)
            {
                foreach (string appropriateContentType in options.RequireCasForContentTypes)
                {
                    if (string.Compare(contentType, appropriateContentType, true, CultureInfo.InvariantCulture) == 0)
                    {
                        contentTypeIsEligible = true;
                        break;
                    }
                }
            }

            foreach (string builtInHandler in options.BypassCasForHandlers)
            {
                if (string.Compare(fileName, builtInHandler, true, CultureInfo.InvariantCulture) == 0)
                {
                    fileNameIsEligible = false;
                    break;
                }
            }

            return (contentTypeIsEligible && fileNameIsEligible);
        }
    }
}
