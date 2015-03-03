//------------------------------------------------------------------------------
// <copyright file="Messages.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>                                                                
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using Microsoft.KeyVault.WebKey;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault
{
    public static class MessagePropertyNames
    {
        public const string Algorithm    = "alg";
        public const string Attributes   = "attributes";        
        public const string Digest       = "digest";        
        public const string Hsm          = "hsm";
        public const string Key          = "key";
        public const string KeyOps       = "key_ops";
        public const string KeySize      = "key_size";
        public const string Kid          = "kid";
        public const string Kty          = "kty";        
        public const string Result       = "result";
        public const string Signature    = "signature";
        public const string Value        = "value";
        public const string Id           = "id";
        public const string NextLink     = "nextLink";
        public const string Tags = "tags";
        public const string ContentType = "contentType";
    }

    #region Key Management   

    [JsonObject]
    public class BackupKeyResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }
    }

    [JsonObject]
    public class GetKeyResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Key, Required = Required.Always )]
        public JsonWebKey Key { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Always )]
        public KeyAttributes Attributes { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Tags, Required = Required.Default)]
        public Dictionary<string, string> Tags { get; set; }
    }

    [JsonObject]
    public class CreateKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kty, Required = Required.Always )]
        public string Kty { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeySize, Required = Required.Default )]
        public int? KeySize { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeyOps, Required = Required.Default )]
        public string[] KeyOps { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Default )]
        public KeyAttributes Attributes { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Tags, Required = Required.Default)]
        public Dictionary<string, string> Tags { get; set; }
    }

    [JsonObject]
    public class ImportKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Key, Required = Required.Always )]
        public JsonWebKey Key { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Hsm, Required = Required.Default )]
        public bool? Hsm { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Default )]
        public KeyAttributes Attributes { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Tags, Required = Required.Default)]
        public Dictionary<string, string> Tags { get; set; }
    }

    [JsonObject]
    public class ListKeyResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kid, Required = Required.Always )]
        public string Kid { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Always )]
        public KeyAttributes Attributes { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Tags, Required = Required.Default)]
        public Dictionary<string, string> Tags { get; set; }
    }

    [JsonObject]
    public class ListKeysResponseMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.Value, Required = Required.Default )]
        public IEnumerable<ListKeyResponseMessage> Value { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.NextLink, Required = Required.Default )]
        public string NextLink { get; set; }
    }

    [JsonObject]
    public class RestoreKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }
    }
  
    [JsonObject]
    public class UpdateKeyRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.KeyOps, Required = Required.Default )]
        public string[] KeyOps { get; set; }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Attributes, Required = Required.Default )]
        public KeyAttributes Attributes { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Tags, Required = Required.Default)]
        public Dictionary<string, string> Tags { get; set; }
    }

    [JsonObject]
    public class DeleteKeyRequestMessage
    {
        // Since DELETE is a POST operation, it must have a body.
        // But so far there is no field.
    }

    #endregion

    #region Key Operations

    [JsonObject]
    public class KeyOpRequestMessage
    {
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Algorithm, Required = Required.Always )]
        public string Alg { get; set; }

        // Data to be encrypted.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }
    }

    [JsonObject]
    public class KeyOpResponseMessage
    {     

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kid, Required = Required.Always )]
        public string Kid { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Default)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value
        {
            get;
            set;
        }

    }

    [JsonObject]
    public class SignRequestMessage : KeyOpRequestMessage
    {
        [OnDeserialized]
        internal void OnDeserialized( StreamingContext context )
        {
            // Detemrine digest length for algorithm.
            // TODO: The wire messages should not contain this level of validation,
            //       this should probably move to the KeyProvider implementatin.
            var digestLength = 0;
            switch ( Alg )
            {
                case JsonWebKeySignatureAlgorithm.RS256:
                    digestLength = 256 / 8; // 256 bits
                    break;

                case JsonWebKeySignatureAlgorithm.RS384:
                    digestLength = 384 / 8; // 384 bits
                    break;

                case JsonWebKeySignatureAlgorithm.RS512:
                    digestLength = 512 / 8; // 512 bits
                    break;

                case JsonWebKeySignatureAlgorithm.RSNULL:
                    break;
            }

            if ( Value != null && digestLength != 0 && Value.Length != digestLength )
                throw new JsonSerializationException( string.Format( System.Globalization.CultureInfo.InvariantCulture, "Invalid digest length: {0} (expected {1} for algorithm \"{2}\".", Value.Length, digestLength, Alg ) );
        }
    }

    [JsonObject]
    public class VerifyRequestMessage : KeyOpRequestMessage
    {
        // Digest to be verified, in Base64URL.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Digest, Required = Required.Always )]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Digest;
    }

    [JsonObject]
    public class VerifyResponseMessage
    {
        [JsonIgnore]
        private bool _value;

        // true if signature was verified, false otherwise.
        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.Result, Required = Required.Default )]
        public bool Result
        {
            get { return _value; }
            set { _value = value; }
        }

        [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.Value, Required = Required.Default )]
        public bool Value
        {
            get { return _value; }
            set { _value = value; }
        }

        public bool ShouldSerializeResult()
        {
            return false;
        }

        public bool ShouldSerializeValue()
        {
            return true;
        }
    }

    #endregion

    //#region Secret Messages

    //[JsonObject]
    //public class ListSecretResponseMessage
    //{
    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Id, Required = Required.Always )]
    //    public string Id { get; set; }
    //}

    //[JsonObject]
    //public class ListSecretsResponseMessage
    //{
    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.Value, Required = Required.Default )]
    //    public IEnumerable<ListSecretResponseMessage> Value { get; set; }

    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Include, NullValueHandling = NullValueHandling.Include, PropertyName = MessagePropertyNames.NextLink, Required = Required.Default )]
    //    public string NextLink { get; set; }
    //}

    //[JsonObject]
    //public class SecretRequestMessage
    //{
    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
    //    public string Value { get; set; }

    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Id, Required = Required.Default )]
    //    public string Id { get; set; }
    //}

    //[JsonObject]
    //public class SecretResponseMessage
    //{
    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always )]
    //    public string Value { get; set; }

    //    [JsonProperty( DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Id, Required = Required.Default )]
    //    public string Id { get; set; }
    //}

    //#endregion

}