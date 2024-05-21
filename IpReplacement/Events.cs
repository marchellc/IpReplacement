using PluginAPI.Events;
using PluginAPI.Core.Attributes;

namespace IpReplacement
{
    public class Events
    {
        [PluginEvent]
        public void OnWaitingForPlayers(WaitingForPlayersEvent ev)
        {
            TokenCache.RemoveAll();
            WhiteList.Reload();
        }
    }
}