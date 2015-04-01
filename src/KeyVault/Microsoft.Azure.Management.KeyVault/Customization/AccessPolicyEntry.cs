using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Microsoft.Azure.Management.KeyVault
{
    public partial class AccessPolicyEntry
    {
        public string[] PermissionsToKeys
        {
            get
            {
                return JsonConvert.DeserializeObject<Dictionary<string, string[]>>(this.PermissionsRawJsonString)["keys"];
            }
            set
            {
                Dictionary<string, string[]> perms = null;
                perms = !string.IsNullOrWhiteSpace(PermissionsRawJsonString) ? JsonConvert.DeserializeObject<Dictionary<string, string[]>>(this.PermissionsRawJsonString) : new Dictionary<string, string[]>();
                perms["keys"] = value;                
                this.PermissionsRawJsonString = JsonConvert.SerializeObject(perms);
            }
        }

        public string[] PermissionsToSecrets
        {
            get
            {
                return JsonConvert.DeserializeObject<Dictionary<string, string[]>>(this.PermissionsRawJsonString)["secrets"];
            }
            set
            {
                Dictionary<string, string[]> perms = null;
                perms = !string.IsNullOrWhiteSpace(PermissionsRawJsonString) ? JsonConvert.DeserializeObject<Dictionary<string, string[]>>(this.PermissionsRawJsonString) : new Dictionary<string, string[]>();
                perms["secrets"] = value;
                this.PermissionsRawJsonString = JsonConvert.SerializeObject(perms);
            }
        }
    }
}
