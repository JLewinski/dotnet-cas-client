using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DotNetCoreCas.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace DotNetCoreCas.Services
{
    public class CasAuthService : ICasAuthService
    {
        public async Task SignIn(HttpContext context, ICasOptions options, ICasPrincipal principal)
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, options.IsCaseSensitive ? principal.Identity.Name : principal.Identity.Name.ToLower()) };
            var claimsIdentity = new ClaimsIdentity(claims, CASDefaults.AuthenticationScheme);

            await context.SignInAsync(CASDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
        }
        public async Task SignOut(HttpContext context, ICasOptions options) => await context.SignOutAsync(CASDefaults.AuthenticationScheme);
    }
}
