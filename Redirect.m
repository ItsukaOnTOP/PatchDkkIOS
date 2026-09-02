#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static void (*OriginalStartRequest)(id, SEL, NSMutableURLRequest *) = NULL;

static void TranscendStartRequest(id self, SEL _cmd, NSMutableURLRequest *request) {
    @autoreleasepool {
        if ([request isKindOfClass:[NSMutableURLRequest class]] && request.URL) {
            NSURLComponents *components =
                [NSURLComponents componentsWithURL:request.URL
                           resolvingAgainstBaseURL:NO];

            if (components) {
                NSString *host = components.host;

                if (host &&
                    [host caseInsensitiveCompare:@"ishin-global.aktsk.com"] == NSOrderedSame) {
                    components.host = @"dokkan-transcend.com";
                }

                // Fix duplicate slashes ONLY in the path.
                // https:// remains untouched.
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

        if (OriginalStartRequest) {
            OriginalStartRequest(self, _cmd, request);
        }
    }
}

__attribute__((constructor))
static void TranscendInit(void) {
    @autoreleasepool {
        Class cls = NSClassFromString(@"HttpAsynConnection");
        if (!cls) {
            NSLog(@"[Transcend] HttpAsynConnection not found");
            return;
        }

        SEL selector = @selector(startRequest:);
        Method method = class_getInstanceMethod(cls, selector);

        if (!method) {
            NSLog(@"[Transcend] startRequest: not found");
            return;
        }

        IMP current = method_getImplementation(method);
        if (current == (IMP)TranscendStartRequest) {
            return;
        }

        OriginalStartRequest =
            (void (*)(id, SEL, NSMutableURLRequest *))current;

        method_setImplementation(method, (IMP)TranscendStartRequest);
        NSLog(@"[Transcend] host redirect hook installed");
    }
}
