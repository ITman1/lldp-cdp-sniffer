#ifndef FRAMES_H
#define FRAMES_H

#include "ethernet_frame.h"

#define LAYER_1                0

enum frames {
    ETHERNET_FRAME  = 0x00000001
};

enum datalink {
    ETHERNET
};

#endif // FRAMES_H
