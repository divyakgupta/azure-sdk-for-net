using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Hyak.Common;

namespace Microsoft.Azure.KeyVault
{
    public class KeyVaultCredential : CloudCredentials
    {
        public delegate string AuthenticationCallback(string authority, string resource, string scope);
        public event AuthenticationCallback OnAuthenticate = null;

        public string Token { get; set; }

        public KeyVaultCredential(AuthenticationCallback authenticationCallback)
        {
            OnAuthenticate = authenticationCallback;
        }

        private string PreAuthenticate(Uri url)
        {
            if (OnAuthenticate != null)
            {
                var challenge = HttpBearerChallengeCache.GetInstance().GetChallengeForURL(url);

                if (challenge != null)
                {
                    return OnAuthenticate(challenge.AuthorizationServer, challenge.Resource, challenge.Scope);
                }
            }

            return null;
        }

        protected string PostAuthenticate(HttpResponseMessage response)
        {
            // An HTTP 401 Not Authorized error; handle if an authentication callback has been supplied
            if (OnAuthenticate != null)
            {
                // Extract the WWW-Authenticate header and determine if it represents an OAuth2 Bearer challenge
                var authenticateHeader = response.Headers.WwwAuthenticate.ElementAt(0).ToString();

                if (HttpBearerChallenge.IsBearerChallenge(authenticateHeader))
                {
                    var challenge = new HttpBearerChallenge(response.RequestMessage.RequestUri, authenticateHeader);

                    if (challenge != null)
                    {
                        // Update challenge cache
                        HttpBearerChallengeCache.GetInstance().SetChallengeForURL(response.RequestMessage.RequestUri, challenge);

                        // We have an authentication challenge, use it to get a new authorization token
                        return OnAuthenticate(challenge.AuthorizationServer, challenge.Resource, challenge.Scope);
                    }
                }
            }

            return null;
        }

        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            var accessToken = PreAuthenticate(request.RequestUri);
            if (!string.IsNullOrEmpty(accessToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            else
            {
                HttpResponseMessage response;
                HttpClient client = new HttpClient();
                using (var r = new HttpRequestMessage(request.Method, request.RequestUri))
                {                    
                    response = await client.SendAsync(r).ConfigureAwait(false);
                }

                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    accessToken = PostAuthenticate(response);

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    }
                }
            }
            
            await base.ProcessHttpRequestAsync(request, cancellationToken);            
        }
    }
}
