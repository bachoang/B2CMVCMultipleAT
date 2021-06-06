using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web.Mvc;

namespace B2CMVCSampleApp.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            if (Request.IsAuthenticated)
            {
                HttpCookie done = HttpContext.Request.Cookies["alldone"];
                if (done == null)
                {
                    HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { });
                    // this is to set some internal state that we need to get another access token for the 2nd web API
                    HttpContext.GetOwinContext().Set<string>("GetAT2", "token2");
                }
            }
            return View();
        }
        /// <summary>
        /// Send an OpenID Connect sign-in request.
        /// Alternatively, you can just decorate the SignIn method with the [Authorize] attribute
        /// </summary>
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        /// <summary>
        /// Send an OpenID Connect sign-out request.
        /// </summary>
        public void SignOut()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(
                    OpenIdConnectAuthenticationDefaults.AuthenticationType,
                    CookieAuthenticationDefaults.AuthenticationType);

            if (Request.Cookies["alldone"] != null)
            {
                Response.Cookies["alldone"].Expires = System.DateTime.Now.AddDays(-1);
            }
        }
    }
}