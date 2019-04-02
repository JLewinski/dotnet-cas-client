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

using System;
using System.Web;
using DotNetCoreCas.Security;
using DotNetCoreCas.Utils;
using DotNetCoreCas.Validation.Schema.Cas20;

namespace DotNetCoreCas.Validation.TicketValidator
{
    /// <summary>
    /// CAS 2.0 Ticket Validator
    /// </summary>
    /// <remarks>
    /// This is the .Net port of org.jasig.cas.client.validation.Cas20ServiceTicketValidator.
    /// </remarks>
    /// <author>Scott Battaglia</author>
    /// <author>Catherine D. Winfrey (.Net)</author>
    /// <author>William G. Thompson, Jr. (.Net)</author>
    /// <author>Marvin S. Addison</author>
    /// <author>Scott Holodak (.Net)</author>
    public class Cas20ServiceTicketValidator : AbstractCasProtocolTicketValidator
    {
        #region Properties
        private string _urlSuffix;
        /// <summary>
        /// The endpoint of the validation URL.  Should be relative (i.e. not start with a "/").
        /// i.e. validate or serviceValidate.
        /// </summary>
        public override string UrlSuffix
        {
            get
            {
                return _urlSuffix;
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Performs Cas20ServiceTicketValidator initialization.
        /// </summary>
        public override void Initialize(Microsoft.AspNetCore.Http.HttpContext context, ICasOptions options)
        {
            if (options.ProxyTicketManager != null)
            {
                _urlSuffix = "proxyValidate";
                CustomParameters.Add("pgtUrl", HttpUtility.UrlEncode(UrlUtil.ConstructProxyCallbackUrl(context, options)));
            }
            else
            {
                _urlSuffix = "serviceValidate";
            }
        }

        /// <summary>
        /// Parses the response from the server into a CAS Assertion and includes this in
        /// a CASPrincipal.
        /// <remarks>
        /// Parsing of a &lt;cas:attributes&gt; element is <b>not</b> supported.  The official
        /// CAS 2.0 protocol does include this feature.  If attributes are needed,
        /// SAML must be used.
        /// </remarks>
        /// </summary>
        /// <param name="response">the response from the server, in any format.</param>
        /// <param name="ticket">The ticket used to generate the validation response</param>
        /// <returns>
        /// a Principal backed by a CAS Assertion, if one could be created from the response.
        /// </returns>
        /// <exception cref="TicketValidationException">
        /// Thrown if creation of the Assertion fails.
        /// </exception>
        protected override ICasPrincipal ParseResponseFromServer(string response, string ticket, ICasOptions options)
        {
            if (String.IsNullOrEmpty(response))
            {
                throw new TicketValidationException("CAS Server response was empty.");
            }

            ServiceResponse serviceResponse;
            try
            {
                serviceResponse = ServiceResponse.ParseResponse(response);
            }
            catch (InvalidOperationException)
            {
                throw new TicketValidationException("CAS Server response does not conform to CAS 2.0 schema");
            }

            if (serviceResponse.IsAuthenticationSuccess)
            {
                AuthenticationSuccess authSuccessResponse = (AuthenticationSuccess)serviceResponse.Item;

                if (String.IsNullOrEmpty(authSuccessResponse.User))
                {
                    throw new TicketValidationException(string.Format("CAS Server response parse failure: missing 'cas:user' element."));
                }

                string proxyGrantingTicketIou = authSuccessResponse.ProxyGrantingTicket;

                if (options.ProxyTicketManager != null && !string.IsNullOrEmpty(proxyGrantingTicketIou))
                {
                    string proxyGrantingTicket = options.ProxyTicketManager.GetProxyGrantingTicket(proxyGrantingTicketIou);
                    if (proxyGrantingTicket != null)
                        options.ProxyTicketManager.InsertProxyGrantingTicketMapping(proxyGrantingTicketIou, proxyGrantingTicket);
                }

                if (authSuccessResponse.Proxies != null && authSuccessResponse.Proxies.Length > 0)
                {
                    return new CasPrincipal(new Assertion(authSuccessResponse.User), proxyGrantingTicketIou, authSuccessResponse.Proxies);
                }
                else
                {
                    return new CasPrincipal(new Assertion(authSuccessResponse.User), proxyGrantingTicketIou);
                }
            }

            if (serviceResponse.IsAuthenticationFailure)
            {
                try
                {
                    AuthenticationFailure authFailureResponse = (AuthenticationFailure)serviceResponse.Item;
                    throw new TicketValidationException(authFailureResponse.Message, authFailureResponse.Code);
                }
                catch
                {
                    throw new TicketValidationException("CAS ticket could not be validated.");
                }
            }

            if (serviceResponse.IsProxySuccess)
            {
                throw new TicketValidationException("Unexpected service validate response: ProxySuccess");
            }

            if (serviceResponse.IsProxyFailure)
            {
                throw new TicketValidationException("Unexpected service validate response: ProxyFailure");
            }

            throw new TicketValidationException("Failed to validate CAS ticket.");
        }
        #endregion
    }
}