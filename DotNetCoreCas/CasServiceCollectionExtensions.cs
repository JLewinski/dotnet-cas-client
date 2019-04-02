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
using DotNetCoreCas;
using DotNetCoreCas.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DotNetCoreCas
{
    /// <summary>
    /// A group of functions used to setup an asp.net core application with CAS
    /// </summary>
    public static class CasServiceCollectionExtensions
    {
        /// <summary>
        /// Adds the CasOptions as a singleton for the MiddleWare to use when setting itself up. This does not enable
        /// authentication in the project. That must be done separately.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <param name="cookieOptions">The options for the Cookie</param>
        /// <returns>The services object to allow for chaining</returns>
        public static AuthenticationBuilder AddCas(this IServiceCollection services, Action<CookieAuthenticationOptions> cookieOptions) => AddCas<CasAuthService>(services, cookieOptions);

        /// <summary>
        /// Adds the CasOptions as a singleton for the MiddleWare to use when setting itself up. This does not enable
        /// authentication in the project. That must be done separately.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <param name="cookieOptions">The options for the Cookie</param>
        /// <returns>The services object to allow for chaining</returns>
        public static AuthenticationBuilder AddCas<T>(this IServiceCollection services, Action<CookieAuthenticationOptions> cookieOptions) where T : class, ICasAuthService
        {
            services.AddScoped<ICasAuthService, T>();
            return services.AddAuthentication(CASDefaults.AuthenticationScheme)
                .AddCookie(CASDefaults.AuthenticationScheme, cookieOptions);
        }

        /// <summary>
        /// Adds the CasOptions as a singleton for the MiddleWare to use when setting itself up. This does not enable
        /// authentication in the project. That must be done separately.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <returns>The services object to allow for chaining</returns>
        public static AuthenticationBuilder AddCas(this IServiceCollection services) => AddCas<CasAuthService>(services);

        /// <summary>
        /// Adds the CasOptions as a singleton for the MiddleWare to use when setting itself up. This does not enable
        /// authentication in the project. That must be done separately.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <returns>The services object to allow for chaining</returns>
        public static AuthenticationBuilder AddCas<T>(this IServiceCollection services) where T : class, ICasAuthService
        {
            return services.AddCas<T>(options => {
                options.LoginPath = "/Cas/Login";
                options.LogoutPath = "/Cas/Logout";
                options.Cookie.Name = "CasAuth";
                options.Cookie.Expiration = new System.TimeSpan(3, 0, 0);
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.ReturnUrlParameter = "redirect";
            });
        }

        /// <summary>
        /// Sets the app to map to use the CasMiddleware when the path starts with the casURL
        /// </summary>
        /// <param name="app">The object to add Cas to</param>
        /// <param name="casURL">The 'controller' that is going to hit CAS. This
        /// should be the same 'controller' for the login url of the cookie auth</param>
        /// <returns>The app object to allow for chaining</returns>
        public static IApplicationBuilder UseCas(this IApplicationBuilder app, string casURL = "/cas/") =>
            UseCasPrivate<CasMiddleware>(app, casURL);

        /// <summary>
        ///  Sets the app to map to use the CasMiddleware when the path starts with the casURL
        /// </summary>
        /// <typeparam name="T">The type of CasMiddleware that the user wants to use</typeparam>
        /// <param name="app">The object to add Cas to</param>
        /// <param name="casURL">The 'controller' that is going to hit CAS. This
        /// should be the same 'controller' for the login url of the cookie auth</param>
        /// <returns></returns>
        public static IApplicationBuilder UseCas<T>(this IApplicationBuilder app, string casURL = "/cas/") where T : CasMiddleware =>
            UseCasPrivate<T>(app, casURL);

        private static IApplicationBuilder UseCasPrivate<T>(this IApplicationBuilder app, string casURL) where T : CasMiddleware =>
            app.MapWhen(context => context.Request.Path.Value.ToLower().StartsWith(casURL.ToLower(), false, null), builder => { builder.UseMiddleware<T>(); });
    }
}