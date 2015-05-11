// 
// Copyright (c) Microsoft and contributors.  All rights reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 
// See the License for the specific language governing permissions and
// limitations under the License.
// 

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Hyak.Common;
using Microsoft.WindowsAzure.Management.StorSimple;
using Microsoft.WindowsAzure.Management.StorSimple.Models;

namespace Microsoft.WindowsAzure.Management.StorSimple
{
    /// <summary>
    /// All Operations related to Virtual Device
    /// </summary>
    internal partial class VirtualDeviceOperations : IServiceOperations<StorSimpleManagementClient>, IVirtualDeviceOperations
    {
        /// <summary>
        /// Initializes a new instance of the VirtualDeviceOperations class.
        /// </summary>
        /// <param name='client'>
        /// Reference to the service client.
        /// </param>
        internal VirtualDeviceOperations(StorSimpleManagementClient client)
        {
            this._client = client;
        }
        
        private StorSimpleManagementClient _client;
        
        /// <summary>
        /// Gets a reference to the
        /// Microsoft.WindowsAzure.Management.StorSimple.StorSimpleManagementClient.
        /// </summary>
        public StorSimpleManagementClient Client
        {
            get { return this._client; }
        }
        
        /// <summary>
        /// The Create Virtual Device
        /// </summary>
        /// <param name='virtualDeviceProvisioningInfo'>
        /// Required. The Virtual device provisioning info.
        /// </param>
        /// <param name='customRequestHeaders'>
        /// Required. The Custom Request Headers which client must use.
        /// </param>
        /// <param name='cancellationToken'>
        /// Cancellation token.
        /// </param>
        /// <returns>
        /// This is the Job Response for all Device Job Related Calls
        /// </returns>
        public async Task<JobResponse> CreateAsync(VirtualDeviceProvisioningInfo virtualDeviceProvisioningInfo, CustomRequestHeaders customRequestHeaders, CancellationToken cancellationToken)
        {
            // Validate
            if (virtualDeviceProvisioningInfo == null)
            {
                throw new ArgumentNullException("virtualDeviceProvisioningInfo");
            }
            if (virtualDeviceProvisioningInfo.DeviceName == null)
            {
                throw new ArgumentNullException("virtualDeviceProvisioningInfo.DeviceName");
            }
            if (virtualDeviceProvisioningInfo.SubNetName == null)
            {
                throw new ArgumentNullException("virtualDeviceProvisioningInfo.SubNetName");
            }
            if (virtualDeviceProvisioningInfo.SubscriptionId == null)
            {
                throw new ArgumentNullException("virtualDeviceProvisioningInfo.SubscriptionId");
            }
            if (virtualDeviceProvisioningInfo.VirtualNetworkName == null)
            {
                throw new ArgumentNullException("virtualDeviceProvisioningInfo.VirtualNetworkName");
            }
            if (customRequestHeaders == null)
            {
                throw new ArgumentNullException("customRequestHeaders");
            }
            
            // Tracing
            bool shouldTrace = TracingAdapter.IsEnabled;
            string invocationId = null;
            if (shouldTrace)
            {
                invocationId = TracingAdapter.NextInvocationId.ToString();
                Dictionary<string, object> tracingParameters = new Dictionary<string, object>();
                tracingParameters.Add("virtualDeviceProvisioningInfo", virtualDeviceProvisioningInfo);
                tracingParameters.Add("customRequestHeaders", customRequestHeaders);
                TracingAdapter.Enter(invocationId, this, "CreateAsync", tracingParameters);
            }
            
            // Construct URL
            string url = "";
            url = url + "/";
            if (this.Client.Credentials.SubscriptionId != null)
            {
                url = url + Uri.EscapeDataString(this.Client.Credentials.SubscriptionId);
            }
            url = url + "/cloudservices/";
            url = url + Uri.EscapeDataString(this.Client.CloudServiceName);
            url = url + "/resources/";
            url = url + Uri.EscapeDataString(this.Client.ResourceNamespace);
            url = url + "/~/";
            url = url + "CisVault";
            url = url + "/";
            url = url + Uri.EscapeDataString(this.Client.ResourceName);
            url = url + "/api/virtualappliance";
            List<string> queryParameters = new List<string>();
            queryParameters.Add("api-version=2014-01-01.1.0");
            if (queryParameters.Count > 0)
            {
                url = url + "?" + string.Join("&", queryParameters);
            }
            string baseUrl = this.Client.BaseUri.AbsoluteUri;
            // Trim '/' character from the end of baseUrl and beginning of url.
            if (baseUrl[baseUrl.Length - 1] == '/')
            {
                baseUrl = baseUrl.Substring(0, baseUrl.Length - 1);
            }
            if (url[0] == '/')
            {
                url = url.Substring(1);
            }
            url = baseUrl + "/" + url;
            url = url.Replace(" ", "%20");
            
            // Create HTTP transport objects
            HttpRequestMessage httpRequest = null;
            try
            {
                httpRequest = new HttpRequestMessage();
                httpRequest.Method = HttpMethod.Post;
                httpRequest.RequestUri = new Uri(url);
                
                // Set Headers
                httpRequest.Headers.Add("Accept", "application/xml");
                httpRequest.Headers.Add("Accept-Language", customRequestHeaders.Language);
                httpRequest.Headers.Add("x-ms-client-request-id", customRequestHeaders.ClientRequestId);
                httpRequest.Headers.Add("x-ms-version", "2014-01-01");
                
                // Set Credentials
                cancellationToken.ThrowIfCancellationRequested();
                await this.Client.Credentials.ProcessHttpRequestAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                
                // Serialize Request
                string requestContent = null;
                XDocument requestDoc = new XDocument();
                
                XElement virtualApplianceProvisioningInfoElement = new XElement(XName.Get("VirtualApplianceProvisioningInfo", "http://windowscloudbackup.com/CiS/V2013_03"));
                requestDoc.Add(virtualApplianceProvisioningInfoElement);
                
                XElement createNewStorageAccountElement = new XElement(XName.Get("CreateNewStorageAccount", "http://windowscloudbackup.com/CiS/V2013_03"));
                createNewStorageAccountElement.Value = virtualDeviceProvisioningInfo.CreateNewStorageAccount.ToString().ToLower();
                virtualApplianceProvisioningInfoElement.Add(createNewStorageAccountElement);
                
                XElement deleteAzureCisVMOnFailureElement = new XElement(XName.Get("DeleteAzureCisVMOnFailure", "http://windowscloudbackup.com/CiS/V2013_03"));
                deleteAzureCisVMOnFailureElement.Value = virtualDeviceProvisioningInfo.DeleteAzureCisVMOnFailure.ToString().ToLower();
                virtualApplianceProvisioningInfoElement.Add(deleteAzureCisVMOnFailureElement);
                
                XElement deviceNameElement = new XElement(XName.Get("DeviceName", "http://windowscloudbackup.com/CiS/V2013_03"));
                deviceNameElement.Value = virtualDeviceProvisioningInfo.DeviceName;
                virtualApplianceProvisioningInfoElement.Add(deviceNameElement);
                
                XElement returnWorkflowIdElement = new XElement(XName.Get("ReturnWorkflowId", "http://windowscloudbackup.com/CiS/V2013_03"));
                returnWorkflowIdElement.Value = virtualDeviceProvisioningInfo.ReturnWorkflowId.ToString().ToLower();
                virtualApplianceProvisioningInfoElement.Add(returnWorkflowIdElement);
                
                if (virtualDeviceProvisioningInfo.StorageAccountName != null)
                {
                    XElement storageAccountNameElement = new XElement(XName.Get("StorageAccountName", "http://windowscloudbackup.com/CiS/V2013_03"));
                    storageAccountNameElement.Value = virtualDeviceProvisioningInfo.StorageAccountName;
                    virtualApplianceProvisioningInfoElement.Add(storageAccountNameElement);
                }
                
                XElement subNetNameElement = new XElement(XName.Get("SubNetName", "http://windowscloudbackup.com/CiS/V2013_03"));
                subNetNameElement.Value = virtualDeviceProvisioningInfo.SubNetName;
                virtualApplianceProvisioningInfoElement.Add(subNetNameElement);
                
                XElement subscriptionIdElement = new XElement(XName.Get("SubscriptionId", "http://windowscloudbackup.com/CiS/V2013_03"));
                subscriptionIdElement.Value = virtualDeviceProvisioningInfo.SubscriptionId;
                virtualApplianceProvisioningInfoElement.Add(subscriptionIdElement);
                
                XElement virtualNetworkNameElement = new XElement(XName.Get("VirtualNetworkName", "http://windowscloudbackup.com/CiS/V2013_03"));
                virtualNetworkNameElement.Value = virtualDeviceProvisioningInfo.VirtualNetworkName;
                virtualApplianceProvisioningInfoElement.Add(virtualNetworkNameElement);
                
                requestContent = requestDoc.ToString();
                httpRequest.Content = new StringContent(requestContent, Encoding.UTF8);
                httpRequest.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/xml");
                
                // Send Request
                HttpResponseMessage httpResponse = null;
                try
                {
                    if (shouldTrace)
                    {
                        TracingAdapter.SendRequest(invocationId, httpRequest);
                    }
                    cancellationToken.ThrowIfCancellationRequested();
                    httpResponse = await this.Client.HttpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                    if (shouldTrace)
                    {
                        TracingAdapter.ReceiveResponse(invocationId, httpResponse);
                    }
                    HttpStatusCode statusCode = httpResponse.StatusCode;
                    if (statusCode != HttpStatusCode.Accepted)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        CloudException ex = CloudException.Create(httpRequest, requestContent, httpResponse, await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false));
                        if (shouldTrace)
                        {
                            TracingAdapter.Error(invocationId, ex);
                        }
                        throw ex;
                    }
                    
                    // Create Result
                    JobResponse result = null;
                    // Deserialize Response
                    if (statusCode == HttpStatusCode.Accepted)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        string responseContent = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                        result = new JobResponse();
                        XDocument responseDoc = XDocument.Parse(responseContent);
                        
                        XElement stringElement = responseDoc.Element(XName.Get("string", "http://schemas.microsoft.com/2003/10/Serialization/"));
                        if (stringElement != null)
                        {
                            string stringInstance = stringElement.Value;
                            result.JobId = stringInstance;
                        }
                        
                    }
                    result.StatusCode = statusCode;
                    if (httpResponse.Headers.Contains("x-ms-request-id"))
                    {
                        result.RequestId = httpResponse.Headers.GetValues("x-ms-request-id").FirstOrDefault();
                    }
                    
                    if (shouldTrace)
                    {
                        TracingAdapter.Exit(invocationId, result);
                    }
                    return result;
                }
                finally
                {
                    if (httpResponse != null)
                    {
                        httpResponse.Dispose();
                    }
                }
            }
            finally
            {
                if (httpRequest != null)
                {
                    httpRequest.Dispose();
                }
            }
        }
    }
}