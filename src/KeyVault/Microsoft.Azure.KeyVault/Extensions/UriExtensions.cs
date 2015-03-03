using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Azure.KeyVault
{
    internal static class UriExtensions
    {
        /// <summary>
        /// Returns an authority string for URI that is guaranteed to contain
        /// a port number.
        /// </summary>
        /// <param name="uri">The Uri from which to compute the authority</param>
        /// <returns>The complete authority for the Uri</returns>
        public static string FullAuthority(this Uri uri)
        {
            string authority = uri.Authority;

            if (!authority.Contains(":"))
            {
                // Append port for complete authority
                authority = string.Format("{0}:{1}", uri.Authority, uri.Port.ToString());
            }

            return authority;
        }

        /// <summary>
        /// x-www-form-urlencoded a string without the requirement for System.Web
        /// </summary>
        /// <param name="String"></param>
        /// <returns></returns>
        // [Obsolete("Use System.Uri.EscapeDataString instead")]
        public static string UrlFormEncode(string text)
        {
            // Sytem.Uri provides reliable parsing
            if (string.IsNullOrEmpty(text))
                return string.Empty;

            return System.Uri.EscapeDataString(text).Replace("%20", "+");
        }

        /// <summary>
        /// UrlDecodes a string without requiring System.Web
        /// </summary>
        /// <param name="text">String to decode.</param>
        /// <returns>decoded string</returns>
        public static string UrlFormDecode(string text)
        {
            if (string.IsNullOrEmpty(text))
                return string.Empty;

            // pre-process for + sign space formatting since System.Uri doesn't handle it
            // plus literals are encoded as %2b normally so this should be safe
            text = text.Replace("+", " ");

            return System.Uri.UnescapeDataString(text);
        }
    }
}
