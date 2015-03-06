# objective-c-jwt-simple

Objective-c implementation of JSON Web Tokens. An easy way to encode and decode a JWT on an iOS/MacOS app.

## Hashing algorithms

- SHA256
- SHA384
- SHA512

## API

#### + (NSString \*) encodeWithPayload:(NSDictionary \*) andKey:(NSString \*) andError:(NSError \**)

- @param payload **JSON to attach**
- @param key **Secret key for encoding**
- @param error **Error object**
- @return token **Jwt**

**Example**

```objective-c
NSError *error;
NSDictionary *payload = @{
                           @"name": @"ducreyna",
                           @"admin": true,
                           @"exp": @1425391188545,
                           @"dic": [[NSDictionary alloc] init]
                        };
NSString *token = [Jwt encodeWithPayload:payload andKey:key andError:&error];
if(token == nil) {
	// Print error
	NSLog(@"Code: %i", [error code]);
	NSLog(@"Reason: %@", [error localizedFailureReason]);
}
```

#### + (NSString \*) encodeWithPayload:(NSDictionary \*) andKey:(NSString \*) andAlgorithm:(AlgorithmType) andError:(NSError \**)

- @param payload **JSON to attach**
- @param key **Secret key for encoding**
- @param algorithm **Algorithm to use**
	- HS256
	- HS384
	- HS512
- @param error **Error object**
- @return token **Jwt**

**Example**

```objective-c
NSError *error;
NSDictionary *payload = @{
                           @"name": @"ducreyna",
                           @"admin": true,
                           @"exp": @1425391188545,
                           @"dic": [[NSDictionary alloc] init]
                        };
NSString *token = [Jwt encodeWithPayload:payload andKey:key andAlgorithm:HS512 andError:&error];
if(token == nil) {
	// Print error
	NSLog(@"Code: %i", [error code]);
	NSLog(@"Reason: %@", [error localizedFailureReason]);
}
```

#### + (NSDictionary \*) decodeWithToken:(NSString \*) andKey:(NSString \*) andVerify:(BOOL) andError:(NSError \**)

- @param token **Jwt to decode**
- @param key **Secret key for decoding**
- @param verify **True if you want to verify the signature**
- @param error **Error object**
- @return decoded **JSON decoded**

**Example**

```objective-c
// Decode a JWT with signature verification
NSError *error;
NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true andError:&error]
if(decoded == nil) {
	// Print error
	NSLog(@"Code: %i", [error code]);
	NSLog(@"Reason: %@", [error localizedFailureReason]);
}
```