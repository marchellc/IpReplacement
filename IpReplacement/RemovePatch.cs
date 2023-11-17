using HarmonyLib;

using Mirror;

using PluginAPI.Core;

namespace IpReplacement
{
    [HarmonyPatch(typeof(CustomNetworkManager), nameof(CustomNetworkManager.OnServerDisconnect))]
    public static class RemovePatch
    {
        public static bool Prefix(NetworkConnectionToClient conn)
        {
            if (conn is null)
            {
                Log.Debug($"Connection is null", Plugin.Config.PatchDebug, "IP Replacement Remove Patch");
                return true;
            }

            Log.Debug($"Removing {conn.connectionId}", Plugin.Config.PatchDebug, "IP Replacement Remove Patch");

            TokenCache.Remove(conn.connectionId);

            return true;
        }
    }
}
