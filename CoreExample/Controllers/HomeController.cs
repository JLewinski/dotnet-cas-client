using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using CoreExample.Models;
using Microsoft.AspNetCore.Authorization;

namespace CoreExample.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Login(string ReturnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return Redirect(ReturnUrl);
            }
            new Microsoft.AspNetCore.Html.HtmlString($"Home/Login?ReturnUrl={ReturnUrl}");
            ViewData["redirect"] = new Microsoft.AspNetCore.Html.HtmlString($"Home/Login&ReturnUrl={ReturnUrl}");
            return View();
        }

        public IActionResult Logout(string ReturnUrl)
        {
            return SignOut();
        }

        public IActionResult UnauthorizedUser()
        {
            return Error();
        }
    }
}
