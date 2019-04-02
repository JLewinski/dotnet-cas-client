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

using DotNetCoreCas.State;
using DotNetCoreCas.Validation.TicketValidator;

namespace DotNetCoreCas
{
    /// <summary>
    /// Added this "unneccessary" interface to allow for CasOptions
    /// to be injected through DI into the CasMiddleware.
    /// </summary>
    public interface ICasOptions
    {
        string ArtifactParameterName { get; set; }
        string AuthenticationType { get; set; }
        string[] BypassCasForHandlers { get; set; }
        string CasProxyCallbackUrl { get; }
        string CasServerLoginUrl { get; set; }
        string CasServerUrlPrefix { get; set; }
        string CookiesRequiredUrl { get; set; }
        bool EncodeServiceUrl { get; set; }
        bool Gateway { get; set; }
        string GatewayParameterName { get; set; }
        string GatewayStatusCookieName { get; set; }
        string LocalHost { get; set; }
        string NotAuthorizedUrl { get; set; }
        string ProxyCallbackParameterName { get; set; }
        string ProxyCallbackUrl { get; set; }
        IProxyTicketManager ProxyTicketManager { get; set; }
        bool RedirectAfterValidation { get; set; }
        bool Renew { get; set; }
        string[] RequireCasForContentTypes { get; set; }
        bool RequireCasForMissingContentTypes { get; set; }
        string ServerName { get; set; }
        string Service { get; set; }
        string ServiceParameterName { get; set; }
        string ServiceTicketManager { get; set; }
        bool SingleSignOut { get; set; }
        long TicketTimeTolerance { get; set; }
        ITicketValidator TicketValidator { get; }
        TicketValidatorNames TicketValidatorName { get; set; }

        void Validate();

        /// <summary>
        /// Sets the case sensitivity for the username.
        /// </summary>
        bool IsCaseSensitive { get; set; }
    }
}