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
    
    // Asserts
    XCTAssertThrows([Jwt encodeWithPayload:payload andKey:nil]);
}

- (void)testKeyDecodeEmpty {
    // Asserts
    XCTAssertThrows([Jwt decodeWithToken:@"token" andKey:nil andVerify:true]);
}

- (void)testTokenEmpty {
    // Asserts
    XCTAssertThrows([Jwt decodeWithToken:@"" andKey:key andVerify:true]);
}

- (void)testBadNumberOfSegments {
    // Asserts
    XCTAssertThrows([Jwt decodeWithToken:@"segment1.segment2" andKey:key andVerify:true]);
}

- (void)testEncode {
    NSDictionary * payload = @{
                               @"devKey": @"nducrey",
                               @"appKey": @"myApp",
                               @"exp": @1425391188545,
                               @"socketId": @"socketId"
                               };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true];
    
    // Asserts
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testEncodeWithAlgorithm {
    NSDictionary * payload = @{
                               @"devKey": @"nducrey",
                               @"appKey": @"myApp",
                               @"exp": @1425391188545,
                               @"socketId": @"socketId"
                               };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key andAlgorithm:HS256];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true];
    
    // Asserts
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testEncodePayloadEmpty {
    NSDictionary *payload = [[NSDictionary alloc] init];
    NSString *token = [Jwt encodeWithPayload:payload andKey:key];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:true];
    
    // Asserts
    XCTAssertEqualObjects(payload, decoded);
}

- (void)testBadToken {
    NSDictionary *payload = @{
                              @"devKey": @"nducrey",
                              @"appKey": @"myApp",
                              @"exp": @1425391188545,
                              @"socketId": @"socketId"
                              };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key];
    token = [token stringByAppendingString:@"IAMJOKER"];
    
    // Asserts
    XCTAssertThrows([Jwt decodeWithToken:token andKey:key andVerify:true]);
}

- (void)testWithoutVerification {
    NSDictionary *payload = @{
                              @"devKey": @"nducrey",
                              @"appKey": @"myApp",
                              @"exp": @1425391188545,
                              @"socketId": @"socketId"
                              };
    NSString *token = [Jwt encodeWithPayload:payload andKey:key];
    token = [token stringByAppendingString:@"IAMBATMAN"];
    NSDictionary *decoded = [Jwt decodeWithToken:token andKey:key andVerify:false];
    
    // Asserts
    XCTAssertEqualObjects(payload, decoded);
}

@end
