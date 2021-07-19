using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using System.Threading;

namespace TeamsSso
{
    public static class TeamsSsoObo
    {
        private static string tenantId = Environment.GetEnvironmentVariable("TenantId");
        private static string clientId = Environment.GetEnvironmentVariable("ClientId");
        private static string clientSecret = Environment.GetEnvironmentVariable("ClientSecret");

        [FunctionName("TeamsSsoObo")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string[] scopes = { "https://graph.microsoft.com/.default" };

            try
            {
                string authority = $"https://login.microsoftonline.com/{tenantId}";

                var app = ConfidentialClientApplicationBuilder.Create(clientId)
                   .WithAuthority(authority)
                   .WithClientSecret(clientSecret)
                   .Build();

                var headers = req.Headers;
                var token = string.Empty;
                if (headers.TryGetValue("Authorization", out var authHeader))
                {
                    if (authHeader[0].StartsWith("Bearer "))
                    {
                        token = authHeader[0].Substring(7, authHeader[0].Length - 7);
                    }
                    else
                    {
                        return new UnauthorizedResult();
                    }
                }

                var issuer = $"https://sts.windows.net/{tenantId}/";
                var audience = $"api://80c398d66a9c.ngrok.io/{clientId}";

                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    issuer + "/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever());

                var validatedToken = await ValidateToken(token, issuer, audience, configurationManager);

                UserAssertion userAssertion = new UserAssertion(validatedToken.Claims.First().Value);
                AuthenticationResult result = await app.AcquireTokenOnBehalfOf(scopes, userAssertion).ExecuteAsync();

                string accessToken = result.AccessToken;
                if (accessToken == null)
                {
                    throw new Exception("Access Token could not be acquired.");
                }
                var myObj = new { access_token = accessToken };
                var jsonToReturn = JsonConvert.SerializeObject(myObj);
                return new OkObjectResult(jsonToReturn);
            }
            catch (Exception ex)
            {
                return new OkObjectResult(ex.Message);
            }
        }

        private static async Task<JwtSecurityToken> ValidateToken(
            string token,
            string issuer,
            string audience,
            IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
            CancellationToken ct = default(CancellationToken))
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                // Allow for some drift in server time
                // (a lower value is better; we recommend two minutes or less)
                ClockSkew = TimeSpan.FromMinutes(2),
                // See additional validation for aud below
            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException)
            {
                // Logging, etc.

                return null;
            }
        }
    }
}
