using System;

using HarmonyLib;

using PluginAPI.Core;
using PluginAPI.Core.Attributes;
using PluginAPI.Events;

namespace IpReplacement
{
    public class Plugin
    {
        public static Config Config { get; private set; }
        public static Plugin Instance { get; private set; }

        [PluginConfig]
        public Config Cfg;

        public Harmony Harmony;

        [PluginEntryPoint(
            "IP Replacement",
            "1.0.0",
            "Replaces Mirror's IP property with the value in the player's auth token.",
            "marchell")]
        public void Load()
        {
            Instance = this;

            Config = Cfg;

            Harmony = new Harmony($"ip.{DateTime.Now.Ticks}");
            Harmony.PatchAll();

            EventManager.RegisterEvents(this, new Events());

            Log.Info("IP replacement loaded and initialized.", "IP Replacement");
        }
    }
}