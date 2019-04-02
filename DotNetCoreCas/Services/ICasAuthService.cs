using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetCoreCas.Security;
using Microsoft.AspNetCore.Http;

namespace DotNetCoreCas.Services
{
    public interface ICasAuthService
    {
        Task SignIn(HttpContext context, ICasOptions options, ICasPrincipal principal);
        Task SignOut(HttpContext context, ICasOptions options);
    }
}
