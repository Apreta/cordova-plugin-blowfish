#import "PBlowfish.h"
#include "blowfish.h"

/*
   Might be more efficient to use Base64 for exchanging with JS
*/

@implementation PBlowfish {
  unsigned char * inBuff;
  size_t inBuffSize;
  unsigned char * outBuff;
  size_t outBuffSize;
  unsigned char * keyBuff;

  CBlowFish coder; 
}

- (id)init
{
  self = [super init];
  if (self)
  {
    inBuff = NULL;
    inBuffSize = 0;
    outBuff = NULL;
    outBuffSize = 0;
    keyBuff = NULL;
  }
  return self;
}

-(void)dealloc
{
  free(inBuff);
  free(outBuff);
  free(keyBuff);
}

- (void)encrypt:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* result;
    NSArray* data = [[command arguments] objectAtIndex:0];
    NSMutableArray* out = [NSMutableArray array];

    int err;
    int inSize = [data count];
    int outSize = inSize;

    if (inSize > inBuffSize)
    {
      if (inBuff)
        inBuff = (unsigned char *)realloc(inBuff, inSize);
      else
        inBuff = (unsigned char *)malloc(inSize);
      inBuffSize = inSize;
    }

    for (int i=0; i<inSize; i++)
    {
      inBuff[i] = [[data objectAtIndex:i] unsignedCharValue];
    }
  
    if (outSize > outBuffSize)
    {
      if (outBuff)
        outBuff = (unsigned char *)realloc(outBuff, outSize);
      else
        outBuff = (unsigned char *)malloc(outSize);
      outBuffSize = outSize;
    }
    
    coder.Encode(inBuff, outBuff, inSize);
  
    for (int i=0; i < outSize; i++)
    {
      [out addObject:[NSNumber numberWithUnsignedChar:outBuff[i] ]];
    }
  
    result = [CDVPluginResult
              resultWithStatus:CDVCommandStatus_OK
              messageAsArray:out];
done:
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* result;
    NSArray* data = [[command arguments] objectAtIndex:0];
    NSMutableArray* out = [NSMutableArray array];
  
    int err;
    int inSize = [data count];
    int outSize = inSize;

    if (inSize > inBuffSize)
    {
      if (inBuff)
        inBuff = (unsigned char *)realloc(inBuff, inSize);
      else
        inBuff = (unsigned char *)malloc(inSize);
      inBuffSize = inSize;
    }

    for (int i=0; i<inSize; i++)
    {
      inBuff[i] = [[data objectAtIndex:i] unsignedCharValue];
    }
  
    if (outSize > outBuffSize)
    {
      if (outBuff)
        outBuff = (unsigned char *)realloc(outBuff, outSize);
      else
        outBuff = (unsigned char *)malloc(outSize);
      outBuffSize = outSize;
    }

    coder.Decode(inBuff, outBuff, inSize);

    for (int i=0; i < outSize; i++)
    {
      [out addObject:[NSNumber numberWithUnsignedChar:outBuff[i] ]];
    }
  
    result = [CDVPluginResult
              resultWithStatus:CDVCommandStatus_OK
              messageAsArray:out];

done:
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void)setKey:(CDVInvokedUrlCommand*)command
{
    NSArray* key = [[command arguments] objectAtIndex:0];

    int inSize = [key count];

    free(keyBuff);
    keyBuff = (unsigned char *)malloc(inSize);

    for (int i=0; i<inSize; i++)
    {
      keyBuff[i] = [[key objectAtIndex:i] unsignedCharValue];
    }

    coder.Initialize(keyBuff, inSize);

    CDVPluginResult* result = [CDVPluginResult
                               resultWithStatus:CDVCommandStatus_OK
                               ];

    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

@end
