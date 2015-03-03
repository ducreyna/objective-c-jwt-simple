//
//  Algorithm.h
//  objective-c-jwt
//
//  Created by Nathan Ducrey on 03/03/2015.
//  Copyright (c) 2015 Nathan Ducrey. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>

#ifndef objective_c_jwt_Algorithm_h
#define objective_c_jwt_Algorithm_h

@interface Algorithm : NSObject

typedef enum  {
    HS256 = 0,
    HS384,
    HS512
} AlgorithmType;

+(NSString *) getValueWithAlgorithmType:(AlgorithmType)algorithmType;
+(int) getDigestLengthWithAlgorithmType:(AlgorithmType)algorithmType;
+(AlgorithmType) getNameWithAlgorithmValue:(NSString *)algorithmValue;

@end

#endif