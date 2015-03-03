//
//  Jwt.h
//  objective-c-jwt
//
//  Created by Nathan Ducrey on 03/03/2015.
//  Copyright (c) 2015 Nathan Ducrey. All rights reserved.
//

#import "Algorithm.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>

@interface Jwt : NSObject

// Encode a JSON Web Token
+(NSString *) encodeWithPayload:(NSDictionary *)payload andKey:(NSString *)key;
+(NSString *) encodeWithPayload:(NSDictionary *)payload andKey:(NSString *)key andAlgorithm:(AlgorithmType)algorithm;

// Decode a JSON Web Token
+(NSDictionary *) decodeWithToken:(NSString *)token andKey:(NSString *)key andVerify:(BOOL) verify;

@end