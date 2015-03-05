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

using Newtonsoft.Json;

namespace Microsoft.Azure.KeyVault
{
    /// <summary>
    /// The attributes of a secret managed by the KeyVault service
    /// </summary>
    [JsonObject]
    public class SecretAttributes
    {
        public const string PropertyEnabled = "enabled";
        public const string PropertyNotBefore = "nbf";
        public const string PropertyExpires = "exp";
        public const string PropertyCreated = "created";
        public const string PropertyUpdated = "updated";

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = PropertyEnabled, Required = Required.Default)]
        public bool? Enabled { get; set; }

        // Not Before Date
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = PropertyNotBefore, Required = Required.Default)]
        public long? NotBefore { get; set; }

        // Expires date
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = PropertyExpires, Required = Required.Default)]
        public long? Expires { get; set; }

        // Created date
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = PropertyCreated, Required = Required.Default)]
        public long? Created { get; set; }

        // Updated date
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = PropertyUpdated, Required = Required.Default)]
        public long? Updated { get; set; }

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <remarks>
        /// The defauts for the properties are:
        /// Enabled   = null
        /// NotBefore = null
        /// Expires   = null
        /// Created   = null
        /// Updated   = null
        /// </remarks>
        public SecretAttributes()
        {
            Enabled = null;
            NotBefore = null;
            Expires = null;
            Created = null;
            Updated = null;
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
