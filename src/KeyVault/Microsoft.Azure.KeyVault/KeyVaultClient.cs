//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Hyak.Common;
using Microsoft.Azure.KeyVault.Internal;
using Microsoft.Azure.KeyVault.WebKey;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault
{
    /// <summary>
    /// Wrapper class around the Hyak generated REST client, to handle custom serialization/deserialization and URL construction
    /// from vault address and key name inputs
    /// </summary>
    public class KeyVaultClient
    {
        public delegate string AuthenticationCallback(string authority, string resource, string scope);

        private KeyVaultInternalClient InternalClient;

        #region Constructor
        public KeyVaultClient(AuthenticationCallback authenticationCallback)
        {
            var credential = new KeyVaultCredential(authenticationCallback);
            InternalClient = new KeyVaultInternalClient(credential);
        }

        public KeyVaultClient(AuthenticationCallback authenticationCallback, HttpClient httpClient)
        {
            var credential = new KeyVaultCredential(authenticationCallback);
            InternalClient = new KeyVaultInternalClient(credential, httpClient);
        }

        public KeyVaultClient(KeyVaultInternalClient internalClient)
        {
            InternalClient = internalClient;
        }
        
        #endregion

        #region Key Crypto Operations
        public async Task<KeyOperationResult> EncryptDataAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] plainText)
        {
            var identifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await EncryptDataAsync(
                identifier.Identifier,
                algorithm,
                plainText);
        }

        public async Task<KeyOperationResult> EncryptDataAsync(string keyIdentifier, string algorithm, byte[] plainText)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.EncryptDataAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, plainText),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);
            });            
        }

        public async Task<KeyOperationResult> DecryptDataAsync(string keyIdentifier, string algorithm, byte[] cipherText)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.DecryptDataAsync(
                        keyIdentifier, 
                        CreateKeyOpRequest(algorithm, cipherText),
                        CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);
            });
        }
                
        public async Task<KeyOperationResult> SignAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] digest)
        {
            var identifier = new KeyIdentifier(vault, keyName, keyVersion);            

            return await SignAsync(
                identifier.Identifier,
                algorithm,
                digest);            
        }

        public async Task<KeyOperationResult> SignAsync(string keyIdentifier, string algorithm, byte[] digest)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.SignAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, digest),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);
            });
        }

        public async Task<bool> VerifyAsync(string keyIdentifier, string algorithm, byte[] digest, byte[] signature)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.VerifyAsync(
                    keyIdentifier,
                    CreateVerifyRequest(algorithm, digest, signature),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<VerifyResponseMessage>(response.KeyOpResponse).Value;
            });
        }

        public async Task<KeyOperationResult> WrapKeyAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] key)
        {
            var identifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await WrapKeyAsync(
                identifier.Identifier,
                algorithm,
                key);
        }

        public async Task<KeyOperationResult> WrapKeyAsync(string keyIdentifier, string algorithm, byte[] key)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.WrapKeyAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, key),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);
            });
        }

        public async Task<KeyOperationResult> UnwrapKeyAsync(string keyIdentifier, string algorithm, byte[] wrappedKey)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.UnwrapKeyAsync(
                    keyIdentifier, 
                    CreateKeyOpRequest(algorithm, wrappedKey),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);
            });
        }

        #endregion

        #region Key Management
        public async Task<KeyBundle> CreateKeyAsync( string vault, string keyName, string keyType, int? keySize = null, string[] key_ops = null, KeyAttributes keyAttributes = null, Dictionary<string, string> tags = null )
        {
            return await Do(async () =>
            {
                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await InternalClient.Keys.CreateAsync(
                    vault, 
                    keyName,
                    CreateKeyRequest(keyType, keySize, key_ops, keyAttributes, tags), 
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });
        }

        public async Task<KeyBundle> GetKeyAsync(string vault, string keyName, string keyVersion = null)
        {
            var keyIdentifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await GetKeyAsync(keyIdentifier.Identifier);
        }

        public async Task<KeyBundle> GetKeyAsync(string keyIdentifier)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.GetAsync(keyIdentifier, CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });
        }

        public async Task<ListKeysResponseMessage> GetKeysAsync(string vault, int? maxresults = null)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.ListAsync(vault, maxresults);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);
            });
        }

        public async Task<ListKeysResponseMessage> GetKeysNextAsync(string nextLink)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.ListNextAsync(nextLink);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);
            });
        }

        public async Task<ListKeysResponseMessage> GetKeyVersionsAsync(string vault, string keyName, int? maxresults = null)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.ListVersionsAsync(vault, keyName, maxresults);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);
            });
        }

        public async Task<ListKeysResponseMessage> GetKeyVersionsNextAsync(string nextLink)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.ListVersionsNextAsync(nextLink);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);
            });
        }

        public async Task<KeyBundle> DeleteKeyAsync(string vault, string keyName)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.DeleteKeyAsync(vault, keyName, CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });
        }

        public async Task<KeyBundle> UpdateKeyAsync(string vault, string keyName, string[] keyOps = null, KeyAttributes attributes = null, Dictionary<string, string> tags = null)
        {
            var keyIdentifier = new KeyIdentifier(vault, keyName);

            return await UpdateKeyAsync(keyIdentifier.Identifier, keyOps, attributes, tags);
        }

        public async Task<KeyBundle> UpdateKeyAsync(string keyIdentifier, string[] keyOps = null, KeyAttributes attributes = null, Dictionary<string, string> tags = null)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.UpdateAsync(
                    keyIdentifier, 
                    CreateUpdateKeyRequest(keyOps, attributes, tags),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });
        }

        public async Task<KeyBundle> ImportKeyAsync( string vault, string keyName, KeyBundle keyBundle, bool? importToHardware = null )
        {
            return await Do(async () =>
            {
                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await InternalClient.Keys.ImportAsync(
                    keyIdentifier.Identifier,
                    CreateImportKeyRequest(importToHardware, keyBundle), 
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });

        }
        
        public async Task<byte[]> BackupKeyAsync( string vault, string keyName )
        {
            return await Do(async () =>
            {
                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await InternalClient.Keys.BackupAsync(keyIdentifier.Identifier, CancellationToken.None);

                return JsonConvert.DeserializeObject<BackupKeyResponseMessage>(response.KeyOpResponse).Value;
            });
        }

        public async Task<KeyBundle> RestoreKeyAsync(string vault, byte[] keyBundleBackup)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Keys.RestoreAsync(
                    vault, 
                    CreateRestoreKeyRequest(keyBundleBackup),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);
            });
        }

        #endregion

        #region Secrets Operations
        public async Task<Secret> GetSecretAsync( string vault, string secretName, string secretVersion = null )
        {
            var secretIdentifier = new SecretIdentifier(vault, secretName, secretVersion);

            return await GetSecretAsync(secretIdentifier.Identifier);
        }

        public async Task<Secret> GetSecretAsync( string secretIdentifier )
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.GetAsync(secretIdentifier, CancellationToken.None);

                return JsonConvert.DeserializeObject<Secret>(response.Response);
            });
        }
        
        public async Task<Secret> SetSecretAsync(string vault, string secretName, SecureString value, Dictionary<string, string> tags = null, string contentType = null, bool enabled = true, bool active = true, bool expired = false)
        {
            var secretIdentifier = new SecretIdentifier(vault, secretName);

            return await SetSecretAsync(secretIdentifier.BaseIdentifier, value, tags, contentType, enabled, active, expired);
        }

        private async Task<Secret> SetSecretAsync(string secretIdentifier, SecureString value, Dictionary<string, string> tags = null, string contentType = null, bool enabled = true, bool active = true, bool expired = false)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.SetAsync(
                    secretIdentifier,
                    CreateSecretRequest(value, tags, contentType, enabled, active, expired),
                    CancellationToken.None);

                return JsonConvert.DeserializeObject<Secret>(response.Response);
            });
        }

        public async Task<Secret> UpdateSecretAsync(string vault, string secretName, string contentType = null, Dictionary<string, string> tags = null, bool enabled = true, bool active = true, bool expired = false)
        {
            var secretIdentifier = new SecretIdentifier(vault, secretName);
            return await UpdateSecretAsync(secretIdentifier.Identifier, contentType, tags, enabled, active, expired);
        }

        public async Task<Secret> UpdateSecretAsync(string secretIdentifier, string contentType = null, Dictionary<string, string> tags = null, bool enabled = true, bool active = true, bool expired = false)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.UpdateAsync(
                    secretIdentifier,
                    CreateUpdateSecretRequest(contentType, tags, enabled, active, expired)
                    );
                return JsonConvert.DeserializeObject<Secret>(response.Response);
            });
        }

        public async Task<Secret> DeleteSecretAsync(string vault, string secretName)
        {
            return await Do(async () =>
            {
                var secretIdentifier = new SecretIdentifier(vault, secretName);

                var response = await InternalClient.Secrets.DeleteAsync(secretIdentifier.BaseIdentifier, CancellationToken.None);

                return JsonConvert.DeserializeObject<Secret>(response.Response);
            });
        }

        public async Task<Secret> DeleteSecretAsync(string secretIdentifier)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.DeleteAsync(secretIdentifier, CancellationToken.None);

                return JsonConvert.DeserializeObject<Secret>(response.Response);
            });
        }

        public async Task<ListSecretsResponseMessage> GetSecretsAsync(string vault, int? maxresults = null )
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.ListAsync(vault, maxresults);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);
            });
        }

        public async Task<ListSecretsResponseMessage> GetSecretsNextAsync(string nextLink)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.ListNextAsync(nextLink);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);
            });
        }

        public async Task<ListSecretsResponseMessage> GetSecretVersionsAsync(string vault, string secretName, int? maxresults = null)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.ListVersionsAsync(vault, secretName, maxresults);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);
            });
        }

        public async Task<ListSecretsResponseMessage> GetSecretVersionsNextAsync(string nextLink)
        {
            return await Do(async () =>
            {
                var response = await InternalClient.Secrets.ListVersionsNextAsync(nextLink);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);
            });
        }

        #endregion

        #region Helper Methods
        public async Task<T> Do<T>(Func<Task<T>> func)
        {
            try
            {
                return await func();
            }
            catch (CloudException cloudException)
            {                
                ErrorResponseMessage error = null;
                                    
                var errorText = cloudException.Response.Content;

                try
                {
                    error = JsonConvert.DeserializeObject<ErrorResponseMessage>(errorText);
                }
                catch (Exception)
                {
                    // Error deserialization failed, attempt to get some data for the client
                    error = new ErrorResponseMessage()
                    {
                        Error = new Error()
                        {
                            Code = "Unknown",
                            Message = string.Format(
                                "HTTP {0} Error: {1}, Reason: {2} ", 
                                cloudException.Response.StatusCode.ToString(), 
                                errorText,
                                cloudException.Response.ReasonPhrase),
                        },
                    };
                }
                
                throw new KeyVaultClientException(
                    cloudException.Response.StatusCode, 
                    cloudException.Request.RequestUri, 
                    error != null ? error.Error : null);
            }
        }

        private static SecretAttributes NewSecretAttributes(bool enabled, bool active, bool expired)
        {
            if (!active && expired)
                throw new ArgumentException("Secret cannot be both inactive and expired; math not possible");

            var attributes = new SecretAttributes();
            attributes.Enabled = enabled;

            if (active == false)
            {
                // Set the secret to not be active for 12 hours
                attributes.NotBefore = (DateTime.UtcNow + new TimeSpan(0, 12, 0, 0)).ToUnixTime();
            }

            if (expired)
            {
                // Set the secret to be expired 12 hours ago
                attributes.Expires = (DateTime.UtcNow - new TimeSpan(0, 12, 0, 0)).ToUnixTime();
            }
            return attributes;
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateKeyOpRequest(string algorithm, byte[] plainText)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (plainText == null)
                throw new ArgumentNullException("plainText");

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = new KeyOperationRequest { Alg = algorithm, Value = plainText }.ToString() };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateVerifyRequest(string algorithm, byte[] digest, byte[] signature)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (digest == null)
                throw new ArgumentNullException("digest");

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(new VerifyRequestMessage { Alg = algorithm, Value = signature, Digest = digest }) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateKeyRequest(string keyType, int? keySize = null, string[] key_ops = null, KeyAttributes keyAttributes = null, Dictionary<string, string> tags = null )
        {
            if (string.IsNullOrEmpty(keyType))
                throw new ArgumentNullException("keyType");

            if (!JsonWebKeyType.AllTypes.Contains(keyType))
                throw new ArgumentOutOfRangeException("keyType");

            var request = new CreateKeyRequestMessage { Kty = keyType, KeySize = keySize, KeyOps = key_ops, Attributes = keyAttributes, Tags = tags };

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateUpdateKeyRequest(string[] keyOps = null, KeyAttributes keyAttributes = null, Dictionary<string, string> tags = null)
        {
            var request = new UpdateKeyRequestMessage { KeyOps = keyOps, Attributes = keyAttributes, Tags = tags};

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateImportKeyRequest(bool? hsm, KeyBundle keyBundle)
        {
            var request = new ImportKeyRequestMessage { Hsm = hsm, Key = keyBundle.Key, Attributes = keyBundle.Attributes, Tags = keyBundle.Tags};

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateRestoreKeyRequest(byte[] keyBundleBackup)
        {
            var request = new RestoreKeyRequestMessage { Value = keyBundleBackup };

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static SecretRequestMessageWithRawJsonContent CreateSecretRequest(SecureString value,
            Dictionary<string, string> tags, string contentType, bool enabled, bool active, bool expired)
        {
            var request = new Secret
            {
                Value = value.ConvertToString(),
                ContentType = contentType,
                Tags = tags,
                Attributes = NewSecretAttributes(enabled, active, expired)
            };

            return new SecretRequestMessageWithRawJsonContent() { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static SecretRequestMessageWithRawJsonContent CreateUpdateSecretRequest(string contentType = null,
            Dictionary<string, string> tags = null, bool enabled = true, bool active = true, bool expired = false)
        {
            var request = new Secret
            {                
                ContentType = contentType,
                Tags = tags,
                Attributes = NewSecretAttributes(enabled, active, expired)
            };

            return new SecretRequestMessageWithRawJsonContent() { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }
        #endregion
    }        
}
