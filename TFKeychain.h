#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface TFKeychain : NSObject {}
+ (NSString*)passwordForAccount:(NSString*)account;
+ (BOOL)setPassword:(NSString*)newPasswordString forAccount:(NSString*)account;
@end