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
    /// Client class to perform cryptographic key operations and vault operations
    /// against the Key Vault service.
    /// </summary>
    public class KeyVaultClient
    {
        /// <summary>
        /// The authentication callback delegate which is to be implemented by the client code
        /// </summary>
        /// <param name="authority"> the authority URL </param>
        /// <param name="resource"> resource URL </param>
        /// <param name="scope"> scope </param>
        /// <returns> access token </returns>
        public delegate string AuthenticationCallback(string authority, string resource, string scope);

        private readonly KeyVaultInternalClient _internalClient;

        #region Constructor
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="authenticationCallback">The authentication callback</param>
        public KeyVaultClient(AuthenticationCallback authenticationCallback)
        {
            var credential = new KeyVaultCredential(authenticationCallback);
            _internalClient = new KeyVaultInternalClient(credential);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="authenticationCallback">The authentication callback</param>
        /// <param name="httpClient">Customized HTTP client </param>
        public KeyVaultClient(AuthenticationCallback authenticationCallback, HttpClient httpClient)
        {
            var credential = new KeyVaultCredential(authenticationCallback);
            _internalClient = new KeyVaultInternalClient(credential, httpClient);
        }

        /// <summary>
        /// Constructor for testability
        /// </summary>
        /// <param name="credential">Credential for key vault operations</param>
        /// <param name="handlers">Custom HTTP handlers</param>
        internal KeyVaultClient(KeyVaultCredential credential, DelegatingHandler[] handlers)
        {
            _internalClient = new KeyVaultInternalClient(credential);
            _internalClient = _internalClient.WithHandlers(handlers);
        }

        #endregion

        #region Key Crypto Operations

        /// <summary>
        /// Encrypts a single block of data. The amount of data that may be encrypted is determined
        /// by the target key type and the encryption algorithm, e.g. RSA, RSA_OAEP
        /// </summary>
        /// <param name="vault">The URL of the vault</param>
        /// <param name="keyName">The name of the key</param>
        /// <param name="keyVersion">The version of the key (optional)</param>
        /// <param name="algorithm">The algorithm</param>
        /// <param name="plainText">The plain text</param>
        /// <returns>The encrypted text</returns>
        public async Task<KeyOperationResult> EncryptDataAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] plainText)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (plainText == null)
                throw new ArgumentNullException("plainText");

            var identifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await EncryptDataAsync(
                identifier.Identifier,
                algorithm,
                plainText).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypts a single block of data. The amount of data that may be encrypted is determined
        /// by the target key type and the encryption algorithm, e.g. RSA, RSA_OAEP
        /// </summary>        
        /// <param name="keyIdentifier">The full key identifier</param>
        /// <param name="algorithm">The algorithm</param>
        /// <param name="plainText">The plain text</param>
        /// <returns>The encrypted text</returns>
        public async Task<KeyOperationResult> EncryptDataAsync(string keyIdentifier, string algorithm, byte[] plainText)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (plainText == null)
                throw new ArgumentNullException("plainText");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.EncryptDataAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, plainText),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypts a single block of encrypted data
        /// </summary>
        /// <param name="keyIdentifier">The full key identifier</param>
        /// <param name="algorithm">The algorithm</param>
        /// <param name="cipherText">The cipher text</param>
        /// <returns>The decryption result</returns>
        public async Task<KeyOperationResult> DecryptDataAsync(string keyIdentifier, string algorithm, byte[] cipherText)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (cipherText == null)
                throw new ArgumentNullException("cipherText");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.DecryptDataAsync(
                        keyIdentifier,
                        CreateKeyOpRequest(algorithm, cipherText),
                        CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates a signature from a digest using the specified key in the vault
        /// </summary>
        /// <param name="vault">The URL of the vault</param>
        /// <param name="keyName">The name of the key</param>
        /// <param name="keyVersion">The version of the key (optional)</param>
        /// <param name="algorithm">The signing algorithm </param>
        /// <param name="digest">The digest value to sign</param>
        /// <returns>The signature value</returns>
        public async Task<KeyOperationResult> SignAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] digest)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (digest == null)
                throw new ArgumentNullException("digest");

            var identifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await SignAsync(
                identifier.Identifier,
                algorithm,
                digest).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates a signature from a digest using the specified key in the vault
        /// </summary>
        /// <param name="keyIdentifier"> The global key identifier of the signing key </param>
        /// <param name="algorithm">The signing algorithm </param>
        /// <param name="digest">The digest value to sign</param>
        /// <returns>The signature value</returns>
        public async Task<KeyOperationResult> SignAsync(string keyIdentifier, string algorithm, byte[] digest)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (digest == null)
                throw new ArgumentNullException("digest");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.SignAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, digest),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Verifies a signature using the specified key
        /// </summary>
        /// <param name="keyIdentifier"> The global key identifier of the key used for signing </param>
        /// <param name="algorithm"> The signing/verification algorithm </param>
        /// <param name="digest"> The digest used for signing </param>
        /// <param name="signature"> The signature to be verified </param>
        /// <returns> true if the signature is verified, false otherwise. </returns>
        public async Task<bool> VerifyAsync(string keyIdentifier, string algorithm, byte[] digest, byte[] signature)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (digest == null)
                throw new ArgumentNullException("digest");

            if (signature == null)
                throw new ArgumentNullException("signature");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.VerifyAsync(
                    keyIdentifier,
                    CreateVerifyRequest(algorithm, digest, signature),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<VerifyResponseMessage>(response.KeyOpResponse).Value;

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Wraps a symmetric key using the specified key
        /// </summary>
        /// <param name="vault">The URL of the vault</param>
        /// <param name="keyName">The name of the key</param>
        /// <param name="keyVersion">The version of the key (optional)</param>
        /// <param name="algorithm">The signing algorithm </param>
        /// <param name="key"> The symmetric key </param>
        /// <returns> The wrapped symmetric key </returns>
        public async Task<KeyOperationResult> WrapKeyAsync(string vault, string keyName, string keyVersion, string algorithm, byte[] key)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (key == null)
                throw new ArgumentNullException("key");

            var identifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await WrapKeyAsync(
                identifier.Identifier,
                algorithm,
                key).ConfigureAwait(false);
        }

        /// <summary>
        /// Wraps a symmetric key using the specified key
        /// </summary>
        /// <param name="keyIdentifier"> The global key identifier of the key used for wrapping </param>
        /// <param name="algorithm"> The wrap algorithm </param>
        /// <param name="key"> The symmetric key </param>
        /// <returns> The wrapped symmetric key </returns>
        public async Task<KeyOperationResult> WrapKeyAsync(string keyIdentifier, string algorithm, byte[] key)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (key == null)
                throw new ArgumentNullException("key");

            return await Do(async () =>
            {

                var response = await _internalClient.Keys.WrapKeyAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, key),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Unwraps a symmetric key using the specified key in the vault
        ///     that has initially been used for wrapping the key.
        /// </summary>
        /// <param name="keyIdentifier"> The global key identifier of the wrapping/unwrapping key </param>
        /// <param name="algorithm">The unwrap algorithm</param>
        /// <param name="wrappedKey">The wrapped symmetric key</param>
        /// <returns>The unwrapped symmetric key</returns>
        public async Task<KeyOperationResult> UnwrapKeyAsync(string keyIdentifier, string algorithm, byte[] wrappedKey)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException("algorithm");

            if (wrappedKey == null)
                throw new ArgumentNullException("wrappedKey");

            return await Do(async () =>
            {

                var response = await _internalClient.Keys.UnwrapKeyAsync(
                    keyIdentifier,
                    CreateKeyOpRequest(algorithm, wrappedKey),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyOperationResult>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        #endregion

        #region Key Management

        /// <summary>
        /// Creates a new, named, key in the specified vault.
        /// </summary>
        /// <param name="vault">The URL for the vault in which the key is to be created.</param>
        /// <param name="keyName">The name for the key</param>
        /// <param name="keyType">The type of key to create (one of the valid WebKeyTypes)</param>
        /// <param name="keyAttributes">The attributes of the key</param>        
        /// <param name="keySize">Size of the key</param>
        /// <param name="key_ops">JSON web key operations</param>        
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <returns>A key bundle containing the result of the create request</returns>
        public async Task<KeyBundle> CreateKeyAsync(string vault, string keyName, string keyType, int? keySize = null, string[] key_ops = null, KeyAttributes keyAttributes = null, Dictionary<string, string> tags = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            if (string.IsNullOrEmpty(keyType))
                throw new ArgumentNullException("keyType");

            if (!JsonWebKeyType.AllTypes.Contains(keyType))
                throw new ArgumentOutOfRangeException("keyType");

            return await Do(async () =>
            {

                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await _internalClient.Keys.CreateAsync(
                    vault,
                    keyName,
                    CreateKeyRequest(keyType, keySize, key_ops, keyAttributes, tags),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves the public portion of a key plus its attributes
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyName">The key name</param>
        /// <param name="keyVersion">The key version</param>
        /// <returns>A KeyBundle of the key and its attributes</returns>
        public async Task<KeyBundle> GetKeyAsync(string vault, string keyName, string keyVersion = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            var keyIdentifier = new KeyIdentifier(vault, keyName, keyVersion);

            return await GetKeyAsync(keyIdentifier.Identifier).ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves the public portion of a key plus its attributes
        /// </summary>
        /// <param name="keyIdentifier">The key identifier</param>
        /// <returns>A KeyBundle of the key and its attributes</returns>
        public async Task<KeyBundle> GetKeyAsync(string keyIdentifier)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.GetAsync(keyIdentifier, CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List keys in the specified vault
        /// </summary>
        /// <param name="vault">The URL for the vault containing the keys.</param>
        /// <param name="maxresults">Maximum number of keys to return</param>
        /// <returns>A response message containing a list of keys in the vault along with a link to the next page of keys</returns>   
        public async Task<ListKeysResponseMessage> GetKeysAsync(string vault, int? maxresults = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.ListAsync(vault, maxresults).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the next page of keys
        /// </summary>
        /// <param name="nextLink">nextLink value from a previous call to GetKeys or GetKeysNext</param>
        /// <returns></returns>
        public async Task<ListKeysResponseMessage> GetKeysNextAsync(string nextLink)
        {
            if (string.IsNullOrEmpty(nextLink))
                throw new ArgumentNullException("nextLink");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.ListNextAsync(nextLink).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the versions of the specified key
        /// </summary>
        /// <param name="vault">The URL for the vault containing the key</param>
        /// <param name="keyName">Name of the key</param>
        /// <param name="maxresults">Maximum number of keys to return</param>
        /// <returns>A response message containing a list of keys along with a link to the next page of keys</returns>
        public async Task<ListKeysResponseMessage> GetKeyVersionsAsync(string vault, string keyName, int? maxresults = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.ListVersionsAsync(vault, keyName, maxresults).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the next page of key version
        /// </summary>
        /// <param name="nextLink">nextLink value from a previous call to GetKeyVersions or GetKeyVersionsNext</param>
        /// <returns>A response message containing a list of keys along with a link to the next page of keys</returns>
        public async Task<ListKeysResponseMessage> GetKeyVersionsNextAsync(string nextLink)
        {
            if (string.IsNullOrEmpty(nextLink))
                throw new ArgumentNullException("nextLink");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.ListVersionsNextAsync(nextLink).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListKeysResponseMessage>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes the specified key
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyName">The key name</param>
        /// <returns>The public part of the deleted key</returns>
        public async Task<KeyBundle> DeleteKeyAsync(string vault, string keyName)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.DeleteKeyAsync(vault, keyName, CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the Key Attributes associated with the specified key
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyName">The key name</param>
        /// <param name="keyOps">Json web key operations</param>
        /// <param name="attributes">The new attributes for the key</param>
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <returns> The updated key </returns>
        public async Task<KeyBundle> UpdateKeyAsync(string vault, string keyName, string[] keyOps = null, KeyAttributes attributes = null, Dictionary<string, string> tags = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            var keyIdentifier = new KeyIdentifier(vault, keyName);

            return await UpdateKeyAsync(keyIdentifier.Identifier, keyOps, attributes, tags).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the Key Attributes associated with the specified key
        /// </summary>        
        /// <param name="keyIdentifier">The key identifier</param>
        /// <param name="keyOps">Json web key operations</param>
        /// <param name="attributes">The new attributes for the key</param>
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <returns> The updated key </returns>
        public async Task<KeyBundle> UpdateKeyAsync(string keyIdentifier, string[] keyOps = null, KeyAttributes attributes = null, Dictionary<string, string> tags = null)
        {
            if (string.IsNullOrEmpty(keyIdentifier))
                throw new ArgumentNullException("keyIdentifier");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.UpdateAsync(
                    keyIdentifier,
                    CreateUpdateKeyRequest(keyOps, attributes, tags),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Imports a key into the specified vault
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyName">The key name</param>
        /// <param name="keyBundle"> Key bundle </param>
        /// <param name="importToHardware">Whether to import as a hardware key (HSM) or software key </param>
        /// <returns> Imported key bundle to the vault </returns>
        public async Task<KeyBundle> ImportKeyAsync(string vault, string keyName, KeyBundle keyBundle, bool? importToHardware = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            if (keyBundle == null)
                throw new ArgumentNullException("keyBundle");

            return await Do(async () =>
            {
                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await _internalClient.Keys.ImportAsync(
                    keyIdentifier.Identifier,
                    CreateImportKeyRequest(importToHardware, keyBundle),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);

        }

        /// <summary>
        /// Requests that a backup of the specified key be downloaded to the client.
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyName">The key name</param>
        /// <returns>The backup blob containing the backed up key</returns>
        public async Task<byte[]> BackupKeyAsync(string vault, string keyName)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException("keyName");

            return await Do(async () =>
            {
                var keyIdentifier = new KeyIdentifier(vault, keyName);

                var response = await _internalClient.Keys.BackupAsync(keyIdentifier.Identifier, CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<BackupKeyResponseMessage>(response.KeyOpResponse).Value;

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Restores the backup key in to a vault 
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="keyBundleBackup"> the backup blob associated with a key bundle </param>
        /// <returns> Restored key bundle in the vault </returns>
        public async Task<KeyBundle> RestoreKeyAsync(string vault, byte[] keyBundleBackup)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (keyBundleBackup == null)
                throw new ArgumentNullException("keyBundleBackup");

            return await Do(async () =>
            {
                var response = await _internalClient.Keys.RestoreAsync(
                    vault,
                    CreateRestoreKeyRequest(keyBundleBackup),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<KeyBundle>(response.KeyOpResponse);

            }).ConfigureAwait(false);
        }

        #endregion

        #region Secrets Operations

        /// <summary>
        /// Gets a secret.
        /// </summary>
        /// <param name="vault">The URL for the vault containing the secrets.</param>
        /// <param name="secretName">The name the secret in the given vault.</param>
        /// <param name="secretVersion">The version of the secret (optional)</param>
        /// <returns>A response message containing the secret</returns>
        public async Task<Secret> GetSecretAsync(string vault, string secretName, string secretVersion = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(secretName))
                throw new ArgumentNullException("secretName");

            var secretIdentifier = new SecretIdentifier(vault, secretName, secretVersion);

            return await GetSecretAsync(secretIdentifier.Identifier).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets a secret.
        /// </summary>
        /// <param name="secretIdentifier">The URL for the secret.</param>
        /// <returns>A response message containing the secret</returns>
        public async Task<Secret> GetSecretAsync(string secretIdentifier)
        {
            if (string.IsNullOrEmpty(secretIdentifier))
                throw new ArgumentNullException("secretIdentifier");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.GetAsync(secretIdentifier, CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<Secret>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Sets a secret in the specified vault.
        /// </summary>
        /// <param name="vault">The URL for the vault containing the secrets.</param>
        /// <param name="secretName">The name the secret in the given vault.</param>
        /// <param name="value">The value of the secret.</param>        
        /// <param name="contentType">Type of the secret value</param>
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <param name="secretAttributes">Attributes for the secret</param>      
        /// <returns>A response message containing the updated secret</returns>
        public async Task<Secret> SetSecretAsync(string vault, string secretName, SecureString value, Dictionary<string, string> tags = null, string contentType = null, SecretAttributes secretAttributes = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(secretName))
                throw new ArgumentNullException("secretName");

            var secretIdentifier = new SecretIdentifier(vault, secretName);

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.SetAsync(
                    secretIdentifier.BaseIdentifier,
                    CreateSecretRequest(value, tags, contentType, secretAttributes),
                    CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<Secret>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the attributes associated with the specified secret
        /// </summary>
        /// <param name="vault">The vault name, e.g. https://myvault.vault.azure.net</param>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="contentType">Type of the secret value</param>
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <param name="secretAttributes">Attributes for the secret</param>        
        /// <returns>A response message containing the updated secret</returns>
        public async Task<Secret> UpdateSecretAsync(string vault, string secretName, string contentType = null, Dictionary<string, string> tags = null, SecretAttributes secretAttributes = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(secretName))
                throw new ArgumentNullException("secretName");

            var secretIdentifier = new SecretIdentifier(vault, secretName);

            return await UpdateSecretAsync(secretIdentifier.Identifier, contentType, tags, secretAttributes).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the attributes associated with the specified secret
        /// </summary>        
        /// <param name="secretIdentifier">The URL of the secret</param>
        /// <param name="contentType">Type of the secret value</param>
        /// <param name="tags">Application-specific metadata in the form of key-value pairs</param>
        /// <param name="secretAttributes">Attributes for the secret</param>        
        /// <returns>A response message containing the updated secret</returns>
        public async Task<Secret> UpdateSecretAsync(string secretIdentifier, string contentType = null, Dictionary<string, string> tags = null, SecretAttributes secretAttributes = null)
        {
            if (string.IsNullOrEmpty(secretIdentifier))
                throw new ArgumentNullException("secretIdentifier");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.UpdateAsync(
                    secretIdentifier,
                    CreateUpdateSecretRequest(contentType, tags, secretAttributes)
                    ).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<Secret>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes a secret from the specified vault.
        /// </summary>
        /// <param name="vault">The URL for the vault containing the secrets.</param>
        /// <param name="secretName">The name of the secret in the given vault.</param>
        /// <returns>The deleted secret</returns>
        public async Task<Secret> DeleteSecretAsync(string vault, string secretName)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(secretName))
                throw new ArgumentNullException("secretName");

            return await Do(async () =>
            {
                var secretIdentifier = new SecretIdentifier(vault, secretName);

                var response = await _internalClient.Secrets.DeleteAsync(secretIdentifier.BaseIdentifier, CancellationToken.None).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<Secret>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List secrets in the specified vault
        /// </summary>
        /// <param name="vault">The URL for the vault containing the secrets.</param>
        /// <param name="maxresults">Maximum number of secrets to return</param>
        /// <returns>A response message containing a list of secrets in the vault along with a link to the next page of secrets</returns>              
        public async Task<ListSecretsResponseMessage> GetSecretsAsync(string vault, int? maxresults = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.ListAsync(vault, maxresults).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the next page of secrets
        /// </summary>
        /// <param name="nextLink">nextLink value from a previous call to GetSecrets or GetSecretsNext</param>
        /// <returns>A response message containing a list of secrets in the vault along with a link to the next page of secrets</returns>
        public async Task<ListSecretsResponseMessage> GetSecretsNextAsync(string nextLink)
        {
            if (string.IsNullOrEmpty(nextLink))
                throw new ArgumentNullException("nextLink");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.ListNextAsync(nextLink).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the versions of a secret
        /// </summary>
        /// <param name="vault">The URL for the vault containing the secret</param>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="maxresults">Maximum number of secrets to return</param>
        /// <returns>A response message containing a list of secrets along with a link to the next page of secrets</returns>
        public async Task<ListSecretsResponseMessage> GetSecretVersionsAsync(string vault, string secretName, int? maxresults = null)
        {
            if (string.IsNullOrEmpty(vault))
                throw new ArgumentNullException("vault");

            if (string.IsNullOrEmpty(secretName))
                throw new ArgumentNullException("secretName");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.ListVersionsAsync(vault, secretName, maxresults).ConfigureAwait(false);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);

            }).ConfigureAwait(false);
        }

        /// <summary>
        /// List the next page of versions of a secret
        /// </summary>
        /// <param name="nextLink">nextLink value from a previous call to GetSecretVersions or GetSecretVersionsNext</param>
        /// <returns>A response message containing a list of secrets in the vault along with a link to the next page of secrets</returns>
        public async Task<ListSecretsResponseMessage> GetSecretVersionsNextAsync(string nextLink)
        {
            if (string.IsNullOrEmpty(nextLink))
                throw new ArgumentNullException("nextLink");

            return await Do(async () =>
            {
                var response = await _internalClient.Secrets.ListVersionsNextAsync(nextLink);

                return JsonConvert.DeserializeObject<ListSecretsResponseMessage>(response.Response);
            });
        }

        #endregion

        #region Helper Methods
        public async Task<T> Do<T>(Func<Task<T>> func)
        {
            try
            {
                return await func().ConfigureAwait(false);
            }
            catch (CloudException cloudException)
            {
                ErrorResponseMessage error;

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

        private static KeyOpRequestMessageWithRawJsonContent CreateKeyRequest(string keyType, int? keySize = null, string[] key_ops = null, KeyAttributes keyAttributes = null, Dictionary<string, string> tags = null)
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
            var request = new UpdateKeyRequestMessage { KeyOps = keyOps, Attributes = keyAttributes, Tags = tags };

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateImportKeyRequest(bool? hsm, KeyBundle keyBundle)
        {
            var request = new ImportKeyRequestMessage { Hsm = hsm, Key = keyBundle.Key, Attributes = keyBundle.Attributes, Tags = keyBundle.Tags };

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static KeyOpRequestMessageWithRawJsonContent CreateRestoreKeyRequest(byte[] keyBundleBackup)
        {
            var request = new RestoreKeyRequestMessage { Value = keyBundleBackup };

            return new KeyOpRequestMessageWithRawJsonContent { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static SecretRequestMessageWithRawJsonContent CreateSecretRequest(SecureString value,
            Dictionary<string, string> tags, string contentType, SecretAttributes secretAttributes)
        {
            var request = new Secret
            {
                Value = value.ConvertToString(),
                ContentType = contentType,
                Tags = tags,
                Attributes = secretAttributes
            };

            return new SecretRequestMessageWithRawJsonContent() { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }

        private static SecretRequestMessageWithRawJsonContent CreateUpdateSecretRequest(string contentType = null,
            Dictionary<string, string> tags = null, SecretAttributes secretAttributes = null)
        {
            var request = new Secret
            {
                ContentType = contentType,
                Tags = tags,
                Attributes = secretAttributes
            };

            return new SecretRequestMessageWithRawJsonContent() { RawJsonRequest = JsonConvert.SerializeObject(request) };
        }
        #endregion
    }
}
