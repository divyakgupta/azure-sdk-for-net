using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault
{
    [JsonObject]
    public class KeyOperationRequest
    {

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Algorithm, Required = Required.Always)]
        public string Alg { get; set; }

        // Data to be encrypted.
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = MessagePropertyNames.Value, Required = Required.Always)]
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Value { get; set; }
        
        public override string ToString()
        {            
            return JsonConvert.SerializeObject(this);
        }
    }
}
