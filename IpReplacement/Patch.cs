using System;

using HarmonyLib;

using Mirror;

using PluginAPI.Core;

namespace IpReplacement
{
    [HarmonyPatch(typeof(NetworkConnectionToClient), nameof(NetworkConnectionToClient.address), MethodType.Getter)]
    public static class Patch
    {
        public static bool Prefix(NetworkConnectionToClient __instance, ref string __result)
        {
            try
            {               
                if (Plugin.Config is null || !Plugin.Config.IsEnabled)
                    return true;

                if (!TokenCache.TryGet(__instance.connectionId, out var token))
                {
                    Log.Debug($"Cannot retrieve token for connection ID {__instance.connectionId}", Plugin.Config.PatchDebug, "IP Replacement Patch");
                    return true;
                }

                __result = token.RequestIp;

                Log.Debug($"Replaced IP of {__instance.connectionId} to {token.RequestIp}", Plugin.Config.PatchDebug, "IP Replacement Patch");

                return false;
            }
            catch (Exception ex)
            {
                Log.Error($"The property patch caught an exception!\n{ex}", "IP Replacement Patch");
                return true;
            }
        }
    }
}