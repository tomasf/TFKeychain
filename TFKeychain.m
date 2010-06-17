#import "TFKeychain.h"

@implementation TFKeychain


+ (NSString*)serviceName {
	return [[NSBundle mainBundle] bundleIdentifier];
}



#if TARGET_OS_IPHONE
#pragma mark iOS


+ (NSString*)passwordForAccount:(NSString*)account {
	NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:(id)kCFBooleanTrue, kSecReturnData,
						   kSecClassGenericPassword, kSecClass,
						   account, kSecAttrAccount,
						   [self serviceName], kSecAttrService,
						   nil];
	
	CFDataRef passwordData = NULL;
	OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef*)&passwordData);
	if(status) return nil;
	
	NSString *password = [[[NSString alloc] initWithData:(id)passwordData encoding:NSUTF8StringEncoding] autorelease];
	CFRelease(passwordData);
	return password;	
}


+ (BOOL)setPassword:(NSString*)password forAccount:(NSString*)account {
	NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	NSDictionary *spec = [NSDictionary dictionaryWithObjectsAndKeys:(id)kSecClassGenericPassword, kSecClass,
						  account, kSecAttrAccount,[self serviceName], kSecAttrService, nil];
	
	if(!password) {
		return !SecItemDelete((CFDictionaryRef)spec);
	
	}else if([self passwordForAccount:account]) {
		NSDictionary *update = [NSDictionary dictionaryWithObject:passwordData forKey:(id)kSecValueData];
		return !SecItemUpdate((CFDictionaryRef)spec, (CFDictionaryRef)update);
								
	}else{
		NSMutableDictionary *data = [NSMutableDictionary dictionaryWithDictionary:spec];
		[data setObject:passwordData forKey:(id)kSecValueData];				  
		return !SecItemAdd((CFDictionaryRef)data, NULL);
	}
}




#else
#pragma mark Mac OS X


+ (SecKeychainItemRef)itemForAccount:(NSString*)account {
	SecKeychainItemRef item = NULL;
	NSString *serviceName = [self serviceName];
	
	OSStatus status = SecKeychainFindGenericPassword(NULL, [serviceName lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [serviceName UTF8String],
													 [account lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [account UTF8String],
													 NULL, NULL, &item);
	if(status) return NULL;
	return item;
}


+ (NSString*)passwordForAccount:(NSString*)account {
	SecKeychainItemRef item = [self itemForAccount:account];
	if(!item) return nil;
	
	UInt32 passwordLength;
	void *passwordBuffer;
	
	OSStatus status = SecKeychainItemCopyAttributesAndData(item, NULL, NULL, NULL, &passwordLength, &passwordBuffer);
	if(status) return nil;
	
	NSString *password = [[[NSString alloc] initWithBytes:passwordBuffer length:passwordLength encoding:NSUTF8StringEncoding] autorelease];
	
	SecKeychainItemFreeAttributesAndData(NULL, passwordBuffer);
	return password;
}


+ (BOOL)setPassword:(NSString*)password forAccount:(NSString*)account {
	NSString *serviceName = [self serviceName];
	SecKeychainItemRef item = [self itemForAccount:account];
	
	if(!password) {
		if(item) return !SecKeychainItemDelete(item);
		else return YES;
	
	}else if(item)
		return !SecKeychainItemModifyAttributesAndData(item, NULL, [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [password UTF8String]);
	
	else
		return !SecKeychainAddGenericPassword(NULL, [serviceName lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [serviceName UTF8String],
											   [account lengthOfBytesUsingEncoding:NSUTF8StringEncoding], [account UTF8String],
											   [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],[password UTF8String],
											   NULL);
}


#endif

@end