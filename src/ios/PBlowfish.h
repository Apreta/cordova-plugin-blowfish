#import <Cordova/CDV.h>

@interface PBlowfish : CDVPlugin

- (void) encrypt:(CDVInvokedUrlCommand*)command;
- (void) decrypt:(CDVInvokedUrlCommand*)command;
- (void) setKey:(CDVInvokedUrlCommand*)command;

@end
