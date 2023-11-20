using CentralAuth;

using Cryptography;

using GameCore;

using HarmonyLib;

using Mirror.LiteNetLib4Mirror;

using NorthwoodLib;

using PluginAPI.Core;
using PluginAPI.Events;

using System;
using System.Collections.Generic;

using Log = PluginAPI.Core.Log;

namespace IpReplacement
{
    [HarmonyPatch(typeof(PlayerAuthenticationManager), nameof(PlayerAuthenticationManager.ProcessAuthenticationResponse))]
    public static class TokenCache
    {
        private static readonly Dictionary<int, AuthenticationToken> _tokens = new Dictionary<int, AuthenticationToken>();
        private static readonly object _lock = new object();

        public static IReadOnlyDictionary<int, AuthenticationToken> Tokens => _tokens;

        public static bool TryGet(int connId, out AuthenticationToken token)
        {
            lock (_lock)
                return _tokens.TryGetValue(connId, out token);
        }

        public static void Set(int connId, AuthenticationToken token)
        {
            if (connId < 0)
            {
                Log.Error($"Provided an invalid connection ID.", "Token Cache");
                return;
            }

            if (token is null)
            {
                Log.Error($"Tried to save a null auth token for connId={connId}", "Token Cache");
                return;
            }

            lock (_lock)
            {
                _tokens[connId] = token;
                Log.Debug($"Saved token for {connId}: {token.RequestIp ?? "(null)"}", Plugin.Config?.CacheDebug ?? false, "Token Cache");
            }
        }

        public static void Remove(int connId)
        {
            lock (_lock)
            {
                if (_tokens.Remove(connId))
                    Log.Debug($"Removed token for {connId}", Plugin.Config?.CacheDebug ?? false, "Token Cache");
                else
                    Log.Debug($"Cannot remove token of {connId}; no such key", Plugin.Config?.CacheDebug ?? false, "Token Cache");
            }
        }

        public static void RemoveAll()
        {
            lock (_lock)
            {
                _tokens.Clear();
                Log.Debug($"Removed all tokens.", Plugin.Config?.CacheDebug ?? false, "Token Cache");
            }
        }

        public static bool Prefix(PlayerAuthenticationManager __instance, AuthenticationResponse msg)
        {
            try
            {
                __instance.AuthenticationResponse = msg;

                if (msg.SignedAuthToken != null)
                {
                    if ((msg.EcdhPublicKey is null || msg.EcdhPublicKeySignature is null) && !__instance.isLocalPlayer)
                        __instance.RejectAuthentication("null ECDH public key or public key signature.");
                    else if (msg.SignedAuthToken.TryGetToken<AuthenticationToken>("Authentication", out var authToken, out var error, out var uid))
                    {
                        uid = PlayerAuthenticationManager.RemoveSalt(uid);

                        if (__instance._challenge != authToken.Challenge)
                            __instance.RejectAuthentication("invalid authentication challenge.", uid);
                        else
                        {
                            __instance._challenge = null;

                            if (authToken.PublicKey != msg.PublicKeyHash)
                                __instance.RejectAuthentication("public key hash mismatch", uid);
                            else if (GameCore.Version.PrivateBeta && !authToken.PrivateBetaOwnership)
                                __instance.RejectAuthentication("you don't own the Private Beta Access Pass DLC.", uid);
                            else
                            {
                                if (!__instance.isLocalPlayer)
                                {
                                    var ip = LiteNetLib4MirrorServer.Peers[__instance.connectionToClient.connectionId].EndPoint;

                                    if (ip != null && (!CustomLiteNetLib4MirrorTransport.UserIds.ContainsKey(ip)
                                        || !CustomLiteNetLib4MirrorTransport.UserIds[ip].UserId.Equals(uid, StringComparison.Ordinal))
                                        && !CustomLiteNetLib4MirrorTransport.UserIdFastReload.Contains(uid))
                                    {
                                        __instance._hub.gameConsoleTransmission.SendToClient("UserID mismatch between authentication and preauthentication token.", "red");
                                        __instance._hub.gameConsoleTransmission.SendToClient("Preauth: " + (CustomLiteNetLib4MirrorTransport.UserIds.TryGetValue(ip, out var preauthItem) ? preauthItem.UserId : "(null)"), "red");
                                        __instance._hub.gameConsoleTransmission.SendToClient("Auth: " + uid, "red");
                                        __instance.RejectAuthentication("UserID mismatch between authentication and preauthentication token. Check the game console for more details.", uid, false);

                                        return false;
                                    }

                                    if (ip != null && CustomLiteNetLib4MirrorTransport.UserIds.ContainsKey(ip))
                                        CustomLiteNetLib4MirrorTransport.UserIds.Remove(ip);

                                    if (CustomLiteNetLib4MirrorTransport.UserIdFastReload.Contains(uid))
                                        CustomLiteNetLib4MirrorTransport.UserIdFastReload.Remove(uid);

                                    if (msg.EcdhPublicKey != null && !ECDSA.VerifyBytes(msg.EcdhPublicKey, msg.EcdhPublicKeySignature, msg.PublicKey))
                                        __instance.RejectAuthentication("invalid ECDH exchange public key signature.", uid);
                                    else if (__instance.CheckBans(authToken, uid))
                                    {
                                        Set(__instance.connectionToClient?.connectionId ?? -1, authToken);

                                        if (msg.EcdhPublicKey != null)
                                            __instance._hub.encryptedChannelManager.ServerProcessExchange(msg.EcdhPublicKey);

                                        msg.AuthToken = authToken;

                                        __instance.AuthenticationResponse = msg;

                                        var log = $"{uid} authentificated from endpoint {ip?.ToString() ?? "(null)"} (Real IP: {__instance.connectionToClient.address}). Player ID assigned: {__instance._hub.PlayerId}. Auth token serial number: {msg.AuthToken.Serial}";

                                        ServerConsole.AddLog(log, ConsoleColor.Green);
                                        ServerLogs.AddLog(ServerLogs.Modules.Networking, log, ServerLogs.ServerLogType.ConnectionUpdate);

                                        __instance.FinalizeAuthentication();

                                        if (msg.SignedBadgeToken != null)
                                        {
                                            if (msg.SignedBadgeToken.TryGetToken<BadgeToken>("Badge request", out var badgeToken, out error, out uid))
                                            {
                                                if (badgeToken.Serial != __instance.AuthenticationResponse.AuthToken.Serial)
                                                {
                                                    __instance.RejectAuthentication("token serial number mismatch.");
                                                    return false;
                                                }

                                                if (badgeToken.UserId != Sha.HashToString(Sha.Sha512(__instance.SaltedUserId)))
                                                {
                                                    __instance.RejectBadgeToken("badge token UserID mismatch.");
                                                    return false;
                                                }

                                                if (StringUtils.Base64Decode(badgeToken.Nickname) != __instance._hub.nicknameSync.MyNick)
                                                {
                                                    __instance.RejectBadgeToken("badge token nickname mismatch.");
                                                    return false;
                                                }

                                                msg.BadgeToken = badgeToken;

                                                __instance.AuthenticationResponse = msg;

                                                var perms = ((badgeToken.RaPermissions == 0UL || ServerStatic.PermissionsHandler.NorthwoodAccess) ? ServerStatic.PermissionsHandler.FullPerm : badgeToken.RaPermissions);

                                                if ((badgeToken.Management || badgeToken.GlobalBanning) && CustomNetworkManager.IsVerified)
                                                {
                                                    __instance._hub.serverRoles.GlobalPerms |= 8388608;
                                                    __instance._hub.serverRoles.GlobalPerms |= 1048576;
                                                }

                                                if (__instance.AuthenticationResponse.BadgeToken.OverwatchMode)
                                                    __instance._hub.serverRoles.GlobalPerms |= 4096;

                                                if ((badgeToken.Staff && ServerStatic.PermissionsHandler.NorthwoodAccess) ||
                                                    (badgeToken.RemoteAdmin && ServerStatic.PermissionsHandler.StaffAccess))
                                                    __instance._hub.serverRoles.GlobalPerms |= perms;

                                                if ((badgeToken.BadgeText != null && badgeToken.BadgeText != "(none)")
                                                    || (badgeToken.BadgeColor != null && badgeToken.BadgeColor != "(none)"))
                                                {
                                                    if (__instance._hub.serverRoles.UserBadgePreferences is ServerRoles.BadgePreferences.PreferGlobal || !__instance._hub.serverRoles.BadgeCover
                                                        || __instance._hub.serverRoles.Group is null)
                                                    {
                                                        var shouldHide = msg.HideBadge;

                                                        switch (badgeToken.BadgeType)
                                                        {
                                                            case 0:
                                                                {
                                                                    if (!ConfigFile.ServerConfig.GetBool("hide_patreon_badges_by_default") || CustomNetworkManager.IsVerified)
                                                                    {
                                                                        if (shouldHide)
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = badgeToken.BadgeText;
                                                                            __instance._hub.serverRoles.GlobalHidden = true;
                                                                            __instance._hub.serverRoles.RefreshHiddenTag();
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted, but it's hidden. Use \".gtag\" command in the game console to show your global badge.", "yellow");
                                                                        }
                                                                        else
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = null;
                                                                            __instance._hub.serverRoles.RpcResetFixed();
                                                                            __instance._hub.serverRoles.NetworkGlobalBadge = __instance.AuthenticationResponse.SignedBadgeToken.token;
                                                                            __instance._hub.serverRoles.NetworkGlobalBadgeSignature = __instance.AuthenticationResponse.SignedBadgeToken.signature;
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted.", "cyan");
                                                                        }
                                                                    }

                                                                    break;
                                                                }

                                                            case 1:
                                                                {
                                                                    if (!ConfigFile.ServerConfig.GetBool("hide_staff_badges_by_default"))
                                                                    {
                                                                        if (shouldHide)
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = badgeToken.BadgeText;
                                                                            __instance._hub.serverRoles.GlobalHidden = true;
                                                                            __instance._hub.serverRoles.RefreshHiddenTag();
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted, but it's hidden. Use \".gtag\" command in the game console to show your global badge.", "yellow");
                                                                        }
                                                                        else
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = null;
                                                                            __instance._hub.serverRoles.RpcResetFixed();
                                                                            __instance._hub.serverRoles.NetworkGlobalBadge = __instance.AuthenticationResponse.SignedBadgeToken.token;
                                                                            __instance._hub.serverRoles.NetworkGlobalBadgeSignature = __instance.AuthenticationResponse.SignedBadgeToken.signature;
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted.", "cyan");
                                                                        }
                                                                    }

                                                                    break;
                                                                }

                                                            case 2:
                                                                {
                                                                    if (!ConfigFile.ServerConfig.GetBool("hide_management_badges_by_default"))
                                                                    {
                                                                        if (shouldHide)
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = badgeToken.BadgeText;
                                                                            __instance._hub.serverRoles.GlobalHidden = true;
                                                                            __instance._hub.serverRoles.RefreshHiddenTag();
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted, but it's hidden. Use \".gtag\" command in the game console to show your global badge.", "yellow");
                                                                        }
                                                                        else
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = null;
                                                                            __instance._hub.serverRoles.RpcResetFixed();
                                                                            __instance._hub.serverRoles.NetworkGlobalBadge = __instance.AuthenticationResponse.SignedBadgeToken.token;
                                                                            __instance._hub.serverRoles.NetworkGlobalBadgeSignature = __instance.AuthenticationResponse.SignedBadgeToken.signature;
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted.", "cyan");
                                                                        }
                                                                    }

                                                                    break;
                                                                }

                                                            case 3:
                                                                break;

                                                            default:
                                                                {
                                                                    if (!ConfigFile.ServerConfig.GetBool("hide_patreon_badges_by_default") || CustomNetworkManager.IsVerified)
                                                                    {
                                                                        if (shouldHide)
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = badgeToken.BadgeText;
                                                                            __instance._hub.serverRoles.GlobalHidden = true;
                                                                            __instance._hub.serverRoles.RefreshHiddenTag();
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted, but it's hidden. Use \".gtag\" command in the game console to show your global badge.", "yellow");
                                                                        }
                                                                        else
                                                                        {
                                                                            __instance._hub.serverRoles.HiddenBadge = null;
                                                                            __instance._hub.serverRoles.RpcResetFixed();
                                                                            __instance._hub.serverRoles.NetworkGlobalBadge = __instance.AuthenticationResponse.SignedBadgeToken.token;
                                                                            __instance._hub.serverRoles.NetworkGlobalBadgeSignature = __instance.AuthenticationResponse.SignedBadgeToken.signature;
                                                                            __instance._hub.gameConsoleTransmission.SendToClient("Your global badge has been granted.", "cyan");
                                                                        }
                                                                    }

                                                                    break;
                                                                }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        __instance._hub.gameConsoleTransmission.SendToClient("Your global badge is covered by server badge. Use \".gtag\" command in the game console to show your global badge.", "yellow");
                                                    }

                                                    __instance._hub.serverRoles.FinalizeSetGroup();
                                                }
                                                else
                                                    __instance.RejectBadgeToken(error);
                                            }
                                        }

                                        if (!Player.PlayersUserIds.ContainsKey(__instance.UserId))
                                            Player.PlayersUserIds[__instance.UserId] = __instance._hub;

                                        EventManager.ExecuteEvent(new PlayerJoinedEvent(__instance._hub));
                                    }
                                }
                            }
                        }
                    }
                }
                else
                    __instance.RejectAuthentication("authentification token not provided.");

                return false;
            }
            catch (Exception ex)
            {
                Log.Error($"An exception occured during player authentification, rejecting {__instance.connectionToClient.address}.\n{ex}", "IP Replacement");

                __instance.RejectAuthentication($"An exception occured during authentification!\n{ex}");

                return false;
            }
        }
    }
}
