using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault
{
    [JsonObject]
    public class KeyOperationResult
    {
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Kid, Required = Required.Always)]
        public string Kid { get; set; }

        // Encrypted data.
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }        
    }
}
