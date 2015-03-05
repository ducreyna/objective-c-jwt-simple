//
//  JwtUnitTest.m
//  objective-c-jwt
//
//  Created by Nathan Ducrey on 03/03/2015.
//  Copyright (c) 2015 Nathan Ducrey. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <XCTest/XCTest.h>

#import "Jwt.h"

@interface JwtUnitTest : XCTestCase

@end

@implementation JwtUnitTest

static NSString *const key = @"secret";

- (void)testKeyEncodeEmpty {
    NSDictionary *payload = [[NSDictionary alloc] init];
    NSError *error;
    NSString *token = [Jwt encodeWithPayload:payload andKey:nil andError:&error];
    
    // Asserts
    XCTAssertNil(token);
    XCTAssertEqual([error domain], @"ducreyna.objective-c-jwt.JwtErrorDomain");
    XCTAssertEqual([error code], -1004);
    XCTAssertEqual([error localizedFailureReason], @"Key cannot be nil or empty");
}

- (void)testKeyDecodeEmpty {
    // Asserts
    NSError *error;
    NSDictionary *decoded = [Jwt decodeWithToken:@"token1.token2.token3" andKey:nil andVerify:true andError:&error];
    XCTAssertNil(decoded);
    XCTAssertEqual([error code], -1004);
    XCTAssertEqual([error localizedFailureReason], @"Key cannot be nil or empty");
}

- (void)testTokenEmpty {
    // Asserts
    NSError *error;
    NSDictionary *decoded = [Jwt decodeWithToken:@"" andKey:key andVerify:true andError:&error];
    XCTAssertNil(decoded);
    XCTAssertEqual([error code], -1000);
    XCTAssertEqual([error localizedFailureReason], @"Not enough or too many segments");
}

- (void)testEncode {
    NSDictionary * payload = @{
                               @"devKey": @"nducrey",
                               @"appKey": @"myApp",
                               @"exp": @1425391188545,
                               @"socketId": @"socketId"
                               };
    NSError *error;
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andError:&error];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true andError:&error];
    
    // Asserts
    XCTAssertNil(error);
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testEncodeWithAlgorithm {
    NSDictionary * payload = @{
                               @"devKey": @"nducrey",
                               @"appKey": @"myApp",
                               @"exp": @1425391188545,
                               @"socketId": @"socketId"
                               };
    NSError *error;
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andAlgorithm:HS256 andError:&error];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true andError:&error];
    
    // Asserts
    XCTAssertNil(error);
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testEncodePayloadEmpty {
    NSError *error;
    NSDictionary *payload = [[NSDictionary alloc] init];
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andError:&error];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true andError:&error];
    
    // Asserts
    XCTAssertNil(error);
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testBadToken {
    NSError *error;
    NSDictionary *payload = @{
                              @"devKey": @"nducrey",
                              @"appKey": @"myApp",
                              @"exp": @1425391188545,
                              @"socketId": @"socketId"
                              };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andError:&error];
    token = [token stringByAppendingString:@"IAMJOKER"];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true andError:&error];
    
    // Asserts
    XCTAssertNil(decoded);
    XCTAssertEqual([error code], -1003);
    XCTAssertEqual([error localizedFailureReason], @"Decoding failure: Signature verification failed");
}

- (void)testWithoutVerification {
    NSError *error;
    NSDictionary *payload = @{
                              @"devKey": @"nducrey",
                              @"appKey": @"myApp",
                              @"exp": @1425391188545,
                              @"socketId": @"socketId"
                              };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andError:&error];
    token = [token stringByAppendingString:@"IAMBATMAN"];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:false andError:&error];
    
    // Asserts
    XCTAssertNil(error);
    XCTAssertEqualObjects(payload, decoded);
}

@end
