Interacting with BitShares nodes through P2P protocol.

### About CityHash

You will need to change the source code of the python-cityhash library to correctly generate IV used in encryption. It will not work out-of-box due to code changes during integration into BitShares code.

```diff
diff --git a/include/city.h b/include/city.h
index 94499ce..7080439 100644
--- a/include/city.h
+++ b/include/city.h
@@ -71,8 +71,8 @@ typedef uint32_t uint32;
 typedef uint64_t uint64;
 typedef std::pair<uint64, uint64> uint128;

-inline uint64 Uint128Low64(const uint128& x) { return x.first; }
-inline uint64 Uint128High64(const uint128& x) { return x.second; }
+inline uint64 Uint128Low64(const uint128& x) { return x.second; }
+inline uint64 Uint128High64(const uint128& x) { return x.first; }

 // Hash function for a byte array.
 uint64 CityHash64(const char *buf, size_t len);
```   
