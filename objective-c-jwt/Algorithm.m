//
//  Algorithm.m
//  objective-c-jwt
//
//  Created by Nathan Ducrey on 03/03/2015.
//  Copyright (c) 2015 Nathan Ducrey. All rights reserved.
//

#import "Algorithm.h"

@implementation Algorithm

+(NSString *) getValueWithAlgorithmType:(AlgorithmType)algorithmType {
    NSString *result = nil;
    
    switch(algorithmType) {
        case HS256:
            result = @"HS256";
            break;
        case HS384:
            result = @"HS284";
            break;
        case HS512:
            result = @"HS512";
            break;
        default:
            break;
    }
    
    return result;
}

// ###################################################################################################################################################

+(int) getDigestLengthWithAlgorithmType:(AlgorithmType)algorithmType {
    int result;
    
    switch(algorithmType) {
        case HS256:
            result = CC_SHA256_DIGEST_LENGTH;
            break;
        case HS384:
            result = CC_SHA384_DIGEST_LENGTH;
            break;
        case HS512:
            result = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            break;
    }
    
    return result;
}

// ###################################################################################################################################################

+(AlgorithmType) getNameWithAlgorithmValue:(NSString *)algorithmValue {
    AlgorithmType type;
    
    if([algorithmValue isEqualToString:@"HS256"]) {
        type = HS256;
    } else if([algorithmValue isEqualToString:@"HS384"]) {
        type = HS384;
    } else if([algorithmValue isEqualToString:@"HS512"]) {
        type = HS512;
    } else {
        @throw [NSException exceptionWithName:@"Bad AlgorithmType" reason:@"Algorithm not supported" userInfo:nil];
    }
    
    return type;
}

@end