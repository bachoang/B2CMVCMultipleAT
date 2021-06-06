using Microsoft.Owin;
using Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Web;
using System.Diagnostics;

[assembly: OwinStartup(typeof(B2CMVCSampleApp.Startup))]

namespace B2CMVCSampleApp
{
    public class Startup
    {
        // The Client ID is used by the application to uniquely identify itself to Microsoft identity platform.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        // static string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];

        static string SignUpSignInPolicy = System.Configuration.ConfigurationManager.AppSettings["SusiPolicy"];
        // Authority is the URL for authority, composed of the Microsoft identity platform and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        string B2CAuthority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["B2CAuthority"], SignUpSignInPolicy);


        string MetadataAddr = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["B2CMetaData"], SignUpSignInPolicy);
        string AppSecret = System.Configuration.ConfigurationManager.AppSettings["Secret"];

        string[] scope1 = new string[] { "https://hellob2c.onmicrosoft.com/demoapi/read" };
        string[] scope2 = new string[] { "https://hellob2c.onmicrosoft.com/62608dd6-54d6-455e-8c83-7195c24c4509/read2" };
        /// <summary>
        /// Configure OWIN to use OpenIdConnect
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
         {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Sets the ClientId, authority, RedirectUri as obtained from web.config
                    ClientId = clientId,
                    // Authority = authority,
                    RedirectUri = redirectUri,
                    // PostLogoutRedirectUri is the page that users will be redirected to after sign-out. In this case, it is using the home page
                    PostLogoutRedirectUri = redirectUri,
                    // MetadataAddress = "https://hellob2c.b2clogin.com/hellob2c.onmicrosoft.com/B2C_1_signupsignin1/v2.0/.well-known/openid-configuration",
                    MetadataAddress = MetadataAddr,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    // ResponseType is set to request the code id_token - which contains basic information about the signed-in user
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    // ValidateIssuer set to false to allow personal and work accounts from any organization to sign in to your application
                    // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name
                    // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = false // This is a simplification
                    },
                    // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed
                    }
                }
            );
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var myval = notification.OwinContext.Get<string>("GetAT2");
            if (!string.IsNullOrEmpty(myval))
            {
                // notification.ProtocolMessage.Scope = $"openid profile offline_access https://hellob2c.onmicrosoft.com/62608dd6-54d6-455e-8c83-7195c24c4509/read2";
                notification.ProtocolMessage.Scope = $"openid profile offline_access {scope2[0]}";
                HttpCookie cookie = new HttpCookie("2ndatcookie");
                cookie.Value = "true";
                HttpContext.Current.Response.Cookies.Set(cookie);
            }

            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            // string[] scopes = new string[] { "https://hellob2c.onmicrosoft.com/demoapi/read"};
            // string[] scope2 = new string[] { "https://hellob2c.onmicrosoft.com/62608dd6-54d6-455e-8c83-7195c24c4509/read2" };
            IConfidentialClientApplication app;

            String mycookie = "";
            if (HttpContext.Current.Request.Cookies["2ndatcookie"] != null)
                mycookie = HttpContext.Current.Request.Cookies["2ndatcookie"].Value;

            app = ConfidentialClientApplicationBuilder.Create(clientId)
           // .WithClientSecret("Ph9mBO9Gg98D4S8oq8ks.SlE5u~t.9u.3G")
           .WithClientSecret(AppSecret)
           .WithRedirectUri(redirectUri)
           // .WithB2CAuthority("https://hellob2c.b2clogin.com/tfp/hellob2c.onmicrosoft.com/B2C_1_signupsignin1")
           .WithB2CAuthority(B2CAuthority)
           .Build();

            AuthenticationResult result = null;
            if (String.IsNullOrEmpty(mycookie))
            {
                result = await app.AcquireTokenByAuthorizationCode(scope1, notification.Code).ExecuteAsync();
            }
            else
            {
                result = await app.AcquireTokenByAuthorizationCode(scope2, notification.Code).ExecuteAsync();
                if (result.AccessToken != null)
                {
                    if (HttpContext.Current.Request.Cookies["alldone"] == null)
                    {
                        HttpCookie donecookie = new HttpCookie("alldone");
                        donecookie.Value = "true";
                        HttpContext.Current.Response.Cookies.Set(donecookie);
                        HttpContext.Current.Response.Cookies["2ndatcookie"].Expires = DateTime.Now.AddYears(-1);
                    }

                }
            }

            if (result.AccessToken != null)
            {
                Debug.WriteLine("Access Token: " + result.AccessToken);
            }

        }
    }
}
