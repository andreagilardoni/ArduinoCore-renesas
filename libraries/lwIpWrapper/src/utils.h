#pragma once

inline ip_addr_t fromArduinoIP(const IPAddress& ip) { // FIXME this should be const, and IP address should enable this function call when const
    ip_addr_t res;
    if(ip.type() == arduino::IPv4) {
        if(ip == INADDR_NONE) {
            // res = IP4_ADDR_ANY;
        } else {
            IP_ADDR4(&res, ip[0], ip[1], ip[2], ip[3]);
        }
    } else if(ip.type() == arduino::IPv6) {
        if(ip == INADDR_NONE) {
            // res = IP6_ADDR_ANY;
        } else {
            // FIXME implement this, it could be useful to have a function in the IPAddress class to help this out
        }
    }

    return res;
}
