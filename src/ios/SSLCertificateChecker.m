#import "SSLCertificateChecker.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>


@interface SSLCertificateChecker ()

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;
@property (strong, nonatomic) NSString *_allowedFingerprint;
@property (strong, nonatomic) NSString *_serverDomain;

@end

@implementation SSLCertificateChecker

- (void)check:(CDVInvokedUrlCommand*)command {
    
    NSString *serverURL = [command.arguments objectAtIndex:0];
    NSRange range = [serverURL rangeOfString:@"/Motor"];
    serverURL = [serverURL substringToIndex: range.location];
    serverURL = [serverURL substringFromIndex: 8];
    self._plugin = self;
    self._serverDomain = serverURL;
    self._allowedFingerprint = [command.arguments objectAtIndex:1];
    self._callbackId = command.callbackId;

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:[NSOperationQueue mainQueue]];
    NSURL *url = [NSURL URLWithString: [command.arguments objectAtIndex:0]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:@"GET"];
    NSURLSessionDataTask *data = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        if ((long)httpResponse.statusCode == 0) {
            NSString *resultCode = @"CONNECTION_FAILED";
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:resultCode];
            [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
        }
    }];
    [data resume];
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    BOOL isFingerprintOK = FALSE;
    BOOL isCommonNameOK = FALSE;

    SecTrustRef trustRef = [[challenge protectionSpace] serverTrust];
    SecTrustEvaluate(trustRef, NULL);

    CFIndex count = SecTrustGetCertificateCount(trustRef);

    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, i);
        NSString* fingerprint = [self getFingerprint:certRef];


        CFStringRef commonNameRef = NULL;
        SecCertificateCopyCommonName(certRef, &commonNameRef);
        NSString* commonName = (__bridge NSString *)commonNameRef;
        
        if ([fingerprint caseInsensitiveCompare: self._allowedFingerprint] == NSOrderedSame) {
            isFingerprintOK = TRUE;
        }

        if ([commonName caseInsensitiveCompare: self._serverDomain] == NSOrderedSame) {
            isCommonNameOK = TRUE;
        }
    }

    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    
    NSURLCredential *credential = nil;
    
    credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    
    if (credential) {
        disposition = NSURLSessionAuthChallengeUseCredential;
    } else {
        disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    }
    
    completionHandler(disposition, credential);

    if (isFingerprintOK && isCommonNameOK) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    } 
    else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
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