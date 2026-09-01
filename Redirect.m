#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static void (*orig_startRequest)(id, SEL, NSMutableURLRequest *) = NULL;

static BOOL transcend_shouldTrustProtectionSpace(id self, SEL _cmd, id protectionSpace) {
    return YES;
}

static void transcend_startRequest(id self, SEL _cmd, NSMutableURLRequest *request) {
    @autoreleasepool {
        if (request && request.URL) {
            NSURLComponents *components =
                [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];

            if (components) {
                // Redirect only the exact original host.
                if ([components.host isEqualToString:@"ishin-global.aktsk.com"]) {
                    components.host = @"dokkan-transcend.com";
                }

                // Normalize accidental duplicate slashes in the URL path only.
                // This does NOT touch the "https://" part.
                NSString *path = components.percentEncodedPath ?: @"";
                while ([path containsString:@"//"]) {
                    path = [path stringByReplacingOccurrencesOfString:@"//"
                                                           withString:@"/"];
                }
                components.percentEncodedPath = path;

                NSURL *newURL = components.URL;
                if (newURL) {
                    request.URL = newURL;
                }
            }
        }

        if (orig_startRequest) {
            orig_startRequest(self, _cmd, request);
        }
    }
}

static void install_hooks(void) {
    Class cls = NSClassFromString(@"HttpAsynConnection");
    if (!cls) {
        NSLog(@"[Transcend] HttpAsynConnection not found");
        return;
    }

    Method startMethod = class_getInstanceMethod(cls, @selector(startRequest:));
    if (startMethod) {
        IMP current = method_getImplementation(startMethod);

        // Avoid installing our hook twice.
        if (current != (IMP)transcend_startRequest) {
            orig_startRequest =
                (void (*)(id, SEL, NSMutableURLRequest *))current;
            method_setImplementation(startMethod, (IMP)transcend_startRequest);
            NSLog(@"[Transcend] startRequest: hooked");
        }
    } else {
        NSLog(@"[Transcend] startRequest: method not found");
    }

    Method trustMethod =
        class_getInstanceMethod(cls, @selector(shouldTrustProtectionSpace:));

    if (trustMethod) {
        IMP current = method_getImplementation(trustMethod);
        if (current != (IMP)transcend_shouldTrustProtectionSpace) {
            method_setImplementation(
                trustMethod,
                (IMP)transcend_shouldTrustProtectionSpace
            );
            NSLog(@"[Transcend] shouldTrustProtectionSpace: hooked");
        }
    } else {
        NSLog(@"[Transcend] shouldTrustProtectionSpace: method not found");
    }
}

__attribute__((constructor))
static void transcend_init(void) {
    @autoreleasepool {
        // Run immediately. Classes from the main executable are normally
        // registered by the time an injected dylib constructor executes.
        install_hooks();
    }
}
