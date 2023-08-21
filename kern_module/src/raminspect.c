// Prelude code needed by all kernel modules
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

// Needed for defining custom device files
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>

// Needing for logging functions
#include <linux/printk.h>

// Compile-time configuration options
#include "config.h"

#ifdef RS_CONFIG_QUIET
    void __do_nothing() {}

    #undef pr_info
    #define pr_info(...) __do_nothing()
#endif

// Defines the communication interface with the virtual device
#include "fops.h"

// We have to declare a module license for this to compile
MODULE_LICENSE("GPL");

// The major number the kernel chooses to assign when we create our
// temporary device file.

static int major;

// The minor number we assign to the device file
static int minor = 0;

// Linux categorizes device files into different classes to handle them
// better. This virtual device is exclusively used to communicate with
// this particular kernel module so we don't need to use an existing
// class. It requires us to specify a class regardless, however, so
// we specify the name of a new, custom one.

static char* raminspect_classname = "raminspect_frontend";
static char* raminspect_devname = "raminspect";
static struct class* raminspect_class;

int raminspect_init(void) {
    // Create new device file.
    major = register_chrdev(0, raminspect_devname, &raminspect_fops);

    // Handle errors.
    if(major < 0) pr_alert("Registering device file failed with code: %d", major);

    raminspect_class = class_create(raminspect_classname);
    device_create(raminspect_class, NULL, MKDEV(major, minor), NULL, raminspect_devname);
    return 0;
}

void raminspect_exit(void) {
    // Destroy the device file and class.
    device_destroy(raminspect_class, MKDEV(major, minor));
    class_destroy(raminspect_class);

    // Unregister the device.
    unregister_chrdev(major, raminspect_devname);
}

module_init(raminspect_init);
module_exit(raminspect_exit);