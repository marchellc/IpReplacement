using System.ComponentModel;

namespace IpReplacement
{
    public class Config
    {
        [Description("Whether or not to enable IP replacement.")]
        public bool IsEnabled { get; set; } = true;

        [Description("Whether or not to show debug messages from the Harmony patch.")]
        public bool PatchDebug { get; set; } = true;

        [Description("Whether or not to show debug messages from the token cache.")]
        public bool CacheDebug { get; set; } = true;
    }
}