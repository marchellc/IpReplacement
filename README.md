# IpReplacement
This plugin takes the player's real IP from their authentification token, stores it and replaces it via patching in Mirror's `NetworkConnectionToClient.address` getter, effectively replacing it everywhere. Useful if you need to use a proxy to connect to your server.

# Config
```yaml
# Whether or not to enable IP replacement.
is_enabled: true
# Whether or not to show debug messages from the Harmony patch.
patch_debug: true
# Whether or not to show debug messages from the token cache.
cache_debug: true
```

# Dependencies 
The only required dependency is Harmony (https://github.com/pardeike/Harmony), specifically version `2.2.2`.
