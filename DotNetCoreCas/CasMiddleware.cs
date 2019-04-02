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

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using DotNetCoreCas.Logging;
using DotNetCoreCas.Security;
using DotNetCoreCas.Services;
using DotNetCoreCas.Utils;
using DotNetCoreCas.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace DotNetCoreCas
{
    public class CasMiddleware
    {
        private static readonly Logger logger = new Logger(Category.HttpModule);
        private static readonly Logger configLogger = new Logger(Category.Config);
        private static readonly Logger protoLogger = new Logger(Category.Protocol);
        private static readonly Logger securityLogger = new Logger(Category.Security);

        public CasMiddleware(RequestDelegate next)
        {
        }

        /// <summary>
        /// Hits the CAS server either redirecting to the sign in page or validating a ticket.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="casOptions"></param>
        /// <param name="authService"></param>
        /// <returns></returns>
        public virtual async Task InvokeAsync(HttpContext context, Microsoft.Extensions.Options.IOptions<CasOptions> casOptions, ICasAuthService authService)
        {
            var options = casOptions.Value;
            options.Validate();
            if (options.TicketValidator.UrlSuffix == null)
            {
                //Need to initiallize the ticket validator.
                //Should find a better way to do this on-create
                options.TicketValidator.Initialize(context, options);
            }

            if (context.Request.Path.Value.ToLower().StartsWith("/cas/login"))
            {
                HttpRequest request = context.Request;
                if (!Utils.RequestEvaluator.GetRequestIsAppropriateForCasAuthentication(context, options))
                {
                    logger.Debug("AuthenticateRequest bypassed for " + request.Path.ToUriComponent());
                    context.Response.Redirect(options.NotAuthorizedUrl);
                }

                if (Utils.RequestEvaluator.GetRequestHasCasTicket(context, options))
                {
                    logger.Info("Processing proxy Callback request");
                    await authService.SignIn(context, options, ProcessTicketValidation(context, options));
                }
                else
                {
                    context.Response.Redirect(UrlUtil.ConstructLoginRedirectUrl(context, options));
                }
            }
            else
            {
                await authService.SignOut(context, options);
                context.Response.Redirect(UrlUtil.ConstructSingleSignOutRedirectUrl(context, options));
            }
        }


        /// <summary>
        /// Processes the ticket from the CAS server to make sure it is valid.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="_options"></param>
        /// <returns></returns>
        private ICasPrincipal ProcessTicketValidation(HttpContext context, ICasOptions _options)
        {
            CasAuthenticationTicket casTicket;
            ICasPrincipal principal = null;

            string ticket = context.Request.Query[_options.TicketValidator.ArtifactParameterName];

            try
            {
                // Attempt to authenticate the ticket and resolve to an ICasPrincipal
                principal = _options.TicketValidator.Validate(context, ticket, _options);

                // Save the ticket in the FormsAuthTicket.  Encrypt the ticket and send it as a cookie. 
                casTicket = new CasAuthenticationTicket(
                    ticket,
                    UrlUtil.RemoveCasArtifactsFromUrl(context.Request.rawUrl(_options).AbsoluteUri, _options),
                    context.Request.Host.Host,
                    principal.Assertion
                );

                if (_options.ProxyTicketManager != null && !string.IsNullOrEmpty(principal.ProxyGrantingTicket))
                {
                    casTicket.ProxyGrantingTicketIou = principal.ProxyGrantingTicket;
                    casTicket.Proxies.AddRange(principal.Proxies);
                    string proxyGrantingTicket = _options.ProxyTicketManager.GetProxyGrantingTicket(casTicket.ProxyGrantingTicketIou);
                    if (!string.IsNullOrEmpty(proxyGrantingTicket))
                    {
                        casTicket.ProxyGrantingTicket = proxyGrantingTicket;
                    }
                }

                return principal;
            }
            catch (TicketValidationException e)
            {
                // Leave principal null.  This might not have been a CAS service ticket.
                protoLogger.Error("Ticket validation error: " + e);
            }
            return null;
        }

    }
}