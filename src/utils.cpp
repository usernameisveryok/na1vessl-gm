#include "utils.h"

int sendmessage(Message &msg)
{
    msg.serialize();
    return 0;
}
int receivemessage(Message &msg)
{

    msg.deserialize(receivebuf(msg.length));
    return 0;
}
