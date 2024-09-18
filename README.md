# ims-module

# IMS Module - P-CSCF

## Overview

This module demonstrates the P-CSCF (Proxy-Call Session Control Function) for telecommunication using SIPp. The P-CSCF is a critical component in the IP Multimedia Subsystem (IMS) architecture.

## Demo Functions

The demo includes the following functions through SIPp:

1. **Register**: This function demonstrates the registration process of a user agent with the IMS network.
2. **Make Call**: This function demonstrates making a call between two registered user agents.

## Prerequisites

- SIPp installed on your system.
- Basic understanding of SIP (Session Initiation Protocol) and IMS architecture.

## Running the Demo

### Register

To run the registration demo, use the following SIPp command:

```sh
sipp -sf register.xml -s [username] [P-CSCF_IP]
```

### Make Call

To run the call demo, use the following SIPp command:

```sh
sipp -sf make_call.xml -s [callee_username] [P-CSCF_IP]
```

Replace `[username]`, `[callee_username]`, and `[P-CSCF_IP]` with appropriate values.

## Conclusion

This module provides a basic demonstration of the P-CSCF functions in an IMS network using SIPp. For more detailed information, refer to the official SIPp and IMS documentation.
