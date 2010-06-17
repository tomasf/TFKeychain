#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface TFKeychain : NSObject {}
+ (NSString*)passwordForAccount:(NSString*)account;
+ (BOOL)setPassword:(NSString*)password forAccount:(NSString*)account;
@end