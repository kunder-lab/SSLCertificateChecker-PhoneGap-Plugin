#import "SSLCertificateChecker.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>;

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_allowedFingerprint;
@property (nonatomic, assign) BOOL isFingerprintOK;
@property (nonatomic, assign) BOOL isCommonNameOK;
@property (strong, nonatomic) NSString *_serverDomain;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId serverDomain:(NSString*)serverDomain allowedFingerprint:(NSString*)allowedFingerprint;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId serverDomain:(NSString*)serverDomain allowedFingerprint:(NSString*)allowedFingerprint {
    self._plugin = plugin;
    self._callbackId = callbackId;
    self._serverDomain = serverDomain;
    self._allowedFingerprint = allowedFingerprint;
    self.isFingerprintOK = FALSE;
    self.isCommonNameOK = FALSE;
    return self;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge {
    SecTrustRef trustRef = [[challenge protectionSpace] serverTrust];
    SecTrustEvaluate(trustRef, NULL);
    
    //    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    [connection cancel];
    
    CFIndex count = SecTrustGetCertificateCount(trustRef);
    
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, i);
        NSString* fingerprint = [self getFingerprint:certRef];

        CFStringRef commonNameRef = NULL;
        SecCertificateCopyCommonName(certRef, &commonNameRef);
        NSString commonName = (__bridge NSString *)commonNameRef);
        
        if ([fingerprint caseInsensitiveCompare: self._allowedFingerprint] == NSOrderedSame) {
            self.isFingerprintOK = TRUE;
        }

        if ([commonName caseInsensitiveCompare: self._serverDomain] == NSOrderedSame) {
            self.isCommonNameOK = TRUE;
        }
    }

    if (seld.isFingerprintOK && self.isCommonNameOK) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    } 
    else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return nil;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
    connection = nil;
    NSString *resultCode = @"CONNECTION_FAILED. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    connection = nil;
    if (![self sentResponse]) {
        NSLog(@"Connection was not checked because it was cached. Considering it secure to not break your app.");
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

- (NSString*) getFingerprint: (SecCertificateRef) cert {
    NSData* certData = (__bridge NSData*) SecCertificateCopyData(cert);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(certData.bytes, (CC_LONG)certData.length, digest);//int
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];//3
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        [fingerprint appendFormat:@"%02x ", digest[i]];
    }
    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

@end


@interface SSLCertificateChecker ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation SSLCertificateChecker

- (void)check:(CDVInvokedUrlCommand*)command {
    int cacheSizeMemory = 0*4*1024*1024; // 0MB
    int cacheSizeDisk = 0*32*1024*1024; // 0MB
    NSURLCache *sharedCache = [[NSURLCache alloc] initWithMemoryCapacity:cacheSizeMemory diskCapacity:cacheSizeDisk diskPath:@"nsurlcache"];
    [NSURLCache setSharedURLCache:sharedCache];

    NSString *serverURL = [command.arguments objectAtIndex:0];
    //NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL] cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:6.0];

    CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self//No cambiar self por plugin ya que deja de funcionar
                                                                                     callbackId:command.callbackId
                                                                                     serverDomain: [serverURL substringToIndex:7]
                                                                            allowedFingerprint:[command.arguments objectAtIndex:1]];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];

    if(![[NSURLConnection alloc]initWithRequest:request delegate:delegate]){
        //if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

@end