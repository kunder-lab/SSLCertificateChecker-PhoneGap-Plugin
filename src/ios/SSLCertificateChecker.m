#import "SSLCertificateChecker.h"
#import <openssl/x509.h>
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>;

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_allowedFingerprint;
@property (nonatomic, assign) BOOL isFingerprintOK;
@property (nonatomic, assign) BOOL isCommonNameOK;
@property (nonatomic, assign) NSString *_serverURL;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowedFingerprint:(NSString*)allowedFingerprint;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowedFingerprint:(NSString*)allowedFingerprint {
    self.isFingerprintOK = FALSE;
    self.isCommonNameOK = FALSE;
    self._plugin = plugin;
    self._callbackId = callbackId;
    self._allowedFingerprint = allowedFingerprint;
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
        
        if ([fingerprint caseInsensitiveCompare: self._allowedFingerprint] == NSOrderedSame) {
            self.isFingerprintOK = TRUE;
            break;
        }

        NSData *certificateData = (NSData *) SecCertificateCopyData(certRef);
        const unsigned char *certificateDataBytes = (const unsigned char *)[certificateData bytes];
        X509 *certificateX509 = d2i_X509(NULL, &certificateDataBytes, [certificateData length]);
        NSString *issuerCommonName = CertificateGetIssuerCommonName(certificateX509);
        if ([issuerCommonName caseInsensitiveCompare: self._serverURL]) {
            self.isCommonNameOK = TRUE;
        }
    }

    NSLog(@"sslcheck: %@ %@", self.isFingerprintOK, self.isCommonNameOK);

    if (self.isFingerprintOK && self.isCommonNameOK) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    } else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

- (NSString *) CertificateGetIssuerCommonName(X509 *certificateX509)
{
    NSString *issuer = nil;
    if (certificateX509 != NULL) {
        X509_NAME *issuerX509Name = X509_get_issuer_name(certificateX509);

        if (issuerX509Name != NULL) {
            int nid = OBJ_txt2nid("CN"); // commonname
            int index = X509_NAME_get_index_by_NID(issuerX509Name, nid, -1);

            X509_NAME_ENTRY *issuerNameEntry = X509_NAME_get_entry(issuerX509Name, index);

            if (issuerNameEntry) {
                ASN1_STRING *issuerNameASN1 = X509_NAME_ENTRY_get_data(issuerNameEntry);

                if (issuerNameASN1 != NULL) {
                    unsigned char *issuerName = ASN1_STRING_data(issuerNameASN1);
                    issuer = [NSString stringWithUTF8String:(char *)issuerName];
                }
            }
        }
    }

    return issuer;
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
    self._serverURL = [serverURL substringToIndex:7];
    NSLog(@"_serverURL: %@", self._serverURL);
    //NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL] cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:6.0];

    CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self//No cambiar self por plugin ya que deja de funcionar
                                                                                     callbackId:command.callbackId
                                                                            allowedFingerprint:[command.arguments objectAtIndex:1]];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];

    if(![[NSURLConnection alloc]initWithRequest:request delegate:delegate]){
        //if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

@end
