// If this isn't commented out this enables verbose logging, i.e. the fields
// of every parameter passed to an ioctl handler will be printed to dmesg
//
// Note: RS in the configuration option names stands for raminspect
#define RS_CONFIG_DEBUGGING_ENABLED

// If this isn't commented all 'pr_info' calls are no-ops, meaning that this module
// won't print info-level messages to the logs. This will make DEBUGGING_ENABLED 
// have no effect.
//
// Do note that this does not disable error logging in the event of a failed write,
// since that's almost always undesirable behavior.
// #define RS_CONFIG_QUIET