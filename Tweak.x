#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

%hook HttpAsynConnection

- (BOOL)shouldTrustProtectionSpace:(id)arg1 {
    return YES;
}

- (void)startRequest:(NSMutableURLRequest *)request {
    NSString *origURL = request.URL.absoluteString;
    if ([origURL containsString:@"ishin-global.aktsk.com"]) {
        NSString *newURL = [origURL stringByReplacingOccurrencesOfString:@"ishin-global.aktsk.com"
                                                               withString:@"dokkan-transcend.com"];
        NSURL *url = [NSURL URLWithString:newURL];
        [request setURL:url];
    }
    %orig(request);
}

%end
