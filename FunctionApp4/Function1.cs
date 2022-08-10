using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace FunctionApp4
{
    public class Function1
    {
        private readonly ILogger _logger;

        public Function1(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<Function1>();
        }

        [Function("Function1")]
        public HttpResponseData Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            var certificateKV = Environment.GetEnvironmentVariable("CertificateFromKeyVault");

            _logger.LogInformation("Retrieved Certificate");

            var header = new { alg = "RS256" };
            var claimTemplate = new
            {
                iss = "3MVG9OjW2TAjFKUtXlyB_LCZdl9.7bvM3BVmbz5E1Bbi2EtwOsl5Nf.UpvDsxflILZDYrPUSzWG0toKtTEv8E",
                sub = "tsolakidis@uat.deloitte.gr",
                aud = "https://test.salesforce.com",
                exp = GetExpiryDate(),
                jti = Guid.NewGuid(),
            };

            _logger.LogInformation("Created claim template");

            // encoded header
            var headerSerialized = JsonConvert.SerializeObject(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = ToBase64UrlString(headerBytes);

            _logger.LogInformation("Created encoded header");

            // encoded claim template
            var claimSerialized = JsonConvert.SerializeObject(claimTemplate);
            var claimBytes = Encoding.UTF8.GetBytes(claimSerialized);
            var claimEncoded = ToBase64UrlString(claimBytes);

            _logger.LogInformation("Created encoded claim template");

            // input
            var input = headerEncoded + "." + claimEncoded;
            //var inputBytes = Encoding.UTF8.GetBytes(input);

            _logger.LogInformation("Created input");

            var privateKeyBytes = Convert.FromBase64String(certificateKV.ToString());
            //var certificate = new X509Certificate2(privateKeyBytes, string.Empty);
            _logger.LogInformation("Certificate Loaded...");

            var cert = new X509Certificate2(privateKeyBytes, "",
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            _logger.LogInformation("Certificate X509 created");

            var signingCredentials = new X509SigningCredentials(cert, "RS256");
            var signature = JwtTokenUtilities.CreateEncodedSignature(input, signingCredentials);
            var jwt = headerEncoded + "." + claimEncoded + "." + signature;
            _logger.LogInformation("JWT created and signed successfully!");

            var client = new WebClient
            {
                Encoding = Encoding.UTF8
            };
            var uri = "https://mydei--uat.sandbox.my.salesforce.com/services/oauth2/token";
            var content = new NameValueCollection
            {
                ["assertion"] = jwt,
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            };

            string response = Encoding.UTF8.GetString(client.UploadValues(uri, "POST", content));

            // returns access token
            var responseMessage = JsonConvert.DeserializeObject<dynamic>(response);

            return responseMessage;
        }

        static int GetExpiryDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentUtcTime = DateTime.UtcNow;

            var exp = (int)currentUtcTime.AddMinutes(3).Subtract(utc0).TotalSeconds;

            return exp;
        }

        static string ToBase64UrlString(byte[] input)
        {
            return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
