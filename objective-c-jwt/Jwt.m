//
//  Jwt.m
//  objective-c-jwt
//
//  Created by Nathan Ducrey on 03/03/2015.
//  Copyright (c) 2015 Nathan Ducrey. All rights reserved.
//

#import "Jwt.h"

@implementation Jwt

+(NSDictionary *) decodeWithToken:(NSString *)token andKey:(NSString *)key andVerify:(BOOL)verify andError:(NSError **)error {
    NSArray *segments = [token componentsSeparatedByString:@"."];
    if([segments count] != 3) {
        [Jwt setErrorWithCode:-1000 andReason:@"Not enough or too many segments" andError:error];
        return nil;
    }
    // Check key
    if(key == nil || [key length] == 0) {
        [Jwt setErrorWithCode:-1004 andReason:@"Key cannot be nil or empty" andError:error];
        return nil;
    }
    
    // All segments should be base64
    NSString *headerSeg = segments[0];
    NSString *payloadSeg = segments[1];
    NSString *signatureSeg = segments[2];
    
    // Decode and parse header and payload JSON
    NSDictionary *header = [NSJSONSerialization JSONObjectWithData:[Jwt base64DecodeWithString:headerSeg] options:NSJSONReadingMutableLeaves error:error];
    if(header == nil) {
        [Jwt setErrorWithCode:-1001 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot deserialize header:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    NSDictionary *payload = [NSJSONSerialization JSONObjectWithData:[Jwt base64DecodeWithString:payloadSeg] options:NSJSONReadingMutableLeaves error:error];
    if(payload == nil) {
        [Jwt setErrorWithCode:-1001 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot deserialize payload:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    
    if(verify) {
        AlgorithmType algorithmType = [Algorithm getNameWithAlgorithmValue:header[@"alg"]];
        
        // Verify signature. `sign` will return base64 string
        NSString *signinInput = [[NSArray arrayWithObjects: headerSeg, payloadSeg, nil] componentsJoinedByString:@"."];
        if (![Jwt verifyWithInput:signinInput andKey:key andAlgorithm:algorithmType andSignature:signatureSeg]) {
            [Jwt setErrorWithCode:-1003 andReason:@"Decoding failure: Signature verification failed" andError:error];
            return nil;
        }
    }
    
    return payload;
}

// ###################################################################################################################################################

+(NSString *) encodeWithPayload:(NSDictionary *)payload andKey:(NSString *)key andError:(NSError **)error {
    // Check key
    if(key == nil || [key length] == 0) {
        [Jwt setErrorWithCode:-1004 andReason:@"Key cannot be nil or empty" andError:error];
        return nil;
    }
    
    NSDictionary *header = @{
                             @"typ": @"JWT",
                             @"alg": @"HS256"
                             };
    
    NSData *jsonHeader = [NSJSONSerialization dataWithJSONObject:header options:0 error:error];
    if(jsonHeader == nil) {
        [Jwt setErrorWithCode:-1002 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot serialize header:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    NSData *jsonPayload = [NSJSONSerialization dataWithJSONObject:payload options:0 error:error];
    if(jsonPayload == nil) {
        [Jwt setErrorWithCode:-1002 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot serialize payload:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    
    NSMutableArray *segments = [[NSMutableArray alloc] initWithCapacity:3];
    [segments addObject:[Jwt base64EncodeWithBytes:jsonHeader]];
    [segments addObject:[Jwt base64EncodeWithBytes:jsonPayload]];
    [segments addObject:[Jwt signWithInput:[segments componentsJoinedByString:@"."] andKey:key andAlgorithm:HS256]];
    
    return [segments componentsJoinedByString:@"."];
}

// ###################################################################################################################################################

+(NSString *) encodeWithPayload:(NSObject *)payload andKey:(NSString *)key andAlgorithm:(AlgorithmType)algorithm andError:(NSError **)error {
    // Check key
    if(key == nil || [key length] == 0) {
        [Jwt setErrorWithCode:-1004 andReason:@"Key cannot be nil or empty" andError:error];
        return nil;
    }
    
    NSDictionary *header = @{
                             @"typ": @"JWT",
                             @"alg": [Algorithm getValueWithAlgorithmType:algorithm]
                             };
    
    NSData *jsonHeader = [NSJSONSerialization dataWithJSONObject:header options:0 error:error];
    if(jsonHeader == nil) {
        [Jwt setErrorWithCode:-1002 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot serialize header:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    NSData *jsonPayload = [NSJSONSerialization dataWithJSONObject:payload options:0 error:error];
    if(jsonPayload == nil) {
        [Jwt setErrorWithCode:-1002 andReason:[NSString stringWithFormat:@"%@ %@", @"Cannot serialize payload:", [*error localizedFailureReason]] andError:error];
        return nil;
    }
    
    NSMutableArray *segments = [[NSMutableArray alloc] initWithCapacity:3];
    [segments addObject:[Jwt base64EncodeWithBytes:jsonHeader]];
    [segments addObject:[Jwt base64EncodeWithBytes:jsonPayload]];
    [segments addObject:[Jwt signWithInput:[segments componentsJoinedByString:@"."] andKey:key andAlgorithm:algorithm]];
    
    return [segments componentsJoinedByString:@"."];
}

// ###################################################################################################################################################

+(NSString *) base64EncodeWithBytes:(NSData *) bytes {
    NSString * base64str = [bytes base64EncodedStringWithOptions:0];
    
    return [[[base64str stringByReplacingOccurrencesOfString:@"+" withString:@"-"]
             stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
            stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

// ###################################################################################################################################################

+(NSData *) base64DecodeWithString:(NSString *) string {
    string = [[string stringByReplacingOccurrencesOfString:@"-" withString:@"+"]
              stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    int size = [string length] % 4;
    NSMutableString *segment = [[NSMutableString alloc] initWithString:string];
    for (int i = 0; i < size; i++) {
        [segment appendString:@"="];
    }
    
    return [[NSData alloc] initWithBase64EncodedString:segment options:0];
}

// ###################################################################################################################################################

+(NSString *) signWithInput:(NSString *)input andKey:(NSString *)key andAlgorithm:(AlgorithmType)algorithm {
    const char *cKey = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cInput = [input cStringUsingEncoding:NSASCIIStringEncoding];
    NSData *bytes;
    
    unsigned char cHMAC[[Algorithm getDigestLengthWithAlgorithmType:algorithm]];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cInput, strlen(cInput), cHMAC);
    bytes = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    
    return [Jwt base64EncodeWithBytes:bytes];
}

// ###################################################################################################################################################

+(BOOL) verifyWithInput:(NSString *)input andKey:(NSString *)key andAlgorithm:(AlgorithmType)algorithm andSignature:(NSString *) signature {
    return [signature isEqualToString:[Jwt signWithInput:input andKey:key andAlgorithm:algorithm]];
}

// ###################################################################################################################################################

+(void) setErrorWithCode:(int)code andReason:(NSString *)reason andError:(NSError **)error {
    // Create the error
    NSString *domain = @"ducreyna.objective-c-jwt.JwtErrorDomain";
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionary];
    [userInfo setObject:reason forKey:NSLocalizedFailureReasonErrorKey];
    
    // Populate the error reference.
    *error = [[NSError alloc] initWithDomain:domain code:code userInfo:userInfo];
}

@end